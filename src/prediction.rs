use anyhow::Context;
use dexompiler::Apk;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tensorflow::{Graph, SavedModelBundle, SessionOptions, SessionRunArgs, Tensor};

const CAP: i32 = 512_000;

const PERMS: &'static [&'static str] = &[
    "ACCESS_COARSE_LOCATION",
    "ACCESS_FINE_LOCATION",
    "ACCESS_LOCATION_EXTRA_COMMANDS",
    "ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE",
    "BLUETOOTH",
    "BROADCAST_STICKY",
    "CALL_PHONE",
    "CAMERA",
    "CHANGE_CONFIGURATION",
    "CHANGE_NETWORK_STATE",
    "CHANGE_WIFI_STATE",
    "DISABLE_KEYGUARD",
    "GET_ACCOUNTS",
    "GET_TASKS",
    "INSTALL_PACKAGES",
    "INTERACT_ACROSS_USERS_FULL",
    "INTERNET",
    "KILL_BACKGROUND_PROCESSES",
    "MODIFY_AUDIO_SETTINGS",
    "MODIFY_PHONE_STATE",
    "MOUNT_UNMOUNT_FILESYSTEMS",
    "PROCESS_OUTGOING_CALLS",
    "READ_CONTACTS",
    "READ_EXTERNAL_STORAGE",
    "READ_LOGS",
    "READ_PHONE_STATE",
    "READ_SETTINGS",
    "READ_SMS",
    "READ_USER_DICTIONARY",
    "RECEIVE_BOOT_COMPLETED",
    "RECEIVE_MMS",
    "RECEIVE_SMS",
    "RECEIVE_WAP_PUSH",
    "RECORD_AUDIO",
    "RESTART_PACKAGES",
    "SEND_SMS",
    "SET_WALLPAPER",
    "SYSTEM_ALERT_WINDOW",
    "UPDATE_APP_OPS_STATS",
    "USE_CREDENTIALS",
    "VIBRATE",
    "WAKE_LOCK",
    "WRITE_APN_SETTINGS",
    "WRITE_CONTACTS",
    "WRITE_EXTERNAL_STORAGE",
    "WRITE_INTERNAL_STORAGE",
    "WRITE_SECURE_SETTINGS",
    "WRITE_SETTINGS",
    "WRITE_SMS",
];

#[derive(Debug, Serialize, Deserialize)]
pub struct Prediction {
    #[serde(rename = "det")]
    pub detection: Detection,
    #[serde(rename = "proba")]
    pub probability: f32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detection {
    Adware,
    Banking,
    Benign,
    Riskware,
    Sms,
}

impl TryFrom<usize> for Detection {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Detection::Adware),
            1 => Ok(Detection::Banking),
            2 => Ok(Detection::Benign),
            3 => Ok(Detection::Riskware),
            4 => Ok(Detection::Sms),
            _ => Err(()),
        }
    }
}

pub struct Malceiver {
    graph: Graph,
    bundle: SavedModelBundle,
}

impl Malceiver {
    pub fn new() -> Self {
        let mut graph = Graph::new();
        let bundle = SavedModelBundle::load(
            &SessionOptions::new(), 
            &["serve"], &mut graph, 
            "model.pb"
        )
        .expect("Can't load saved model");
        Self { graph, bundle }
    }

    pub fn predict(&self, apks: &[Apk]) -> anyhow::Result<Vec<Prediction>> {
        let signature = self.bundle
            .meta_graph_def()
            .get_signature("serving_default")
            .unwrap();
        let opcode_sequence_input_info = signature.get_input("opcode_sequence_in").unwrap();
        let method_indices_input_info = signature.get_input("method_indices_in").unwrap();
        let permissions_input_info = signature.get_input("permissions_in").unwrap();
        let output_info = signature.get_output("output_0").unwrap();

        let opcode_sequence_in_op = self.graph
            .operation_by_name_required(&opcode_sequence_input_info.name().name)
            .unwrap();
        let method_indices_in_op = self.graph
            .operation_by_name_required(&method_indices_input_info.name().name)
            .unwrap();
        let permissions_in_op = self.graph
            .operation_by_name_required(&permissions_input_info.name().name)
            .unwrap();
        let output_op = self.graph
            .operation_by_name_required(&output_info.name().name)
            .unwrap();
        let batch_size = apks.len() as u64;
        let mut batch_opcodes = Vec::with_capacity(apks.len());
        let mut batch_indices = Vec::with_capacity(apks.len());
        let mut batch_permissions = Vec::with_capacity(apks.len());
        for apk in apks.iter() {
            let mut opcodes = Vec::new();
            let mut indices = Vec::new();
            let mut index = 0;
            for method in &apk.methods {
                let tmp = index + method.insns.len() as i32;
                opcodes.extend(method.insns.iter().map(|inst| inst.opcode as u8));
                indices.push(index);
                indices.push(tmp - 1);
                index = tmp;
                if index >= CAP {
                    break;
                }
            }
            batch_opcodes.push(opcodes);
            batch_indices.push(indices);
            let apk_perms = if let Some(manifest) = &apk.manifest {
                manifest.permissions.iter().map(|s| s.as_ref()).collect()
            } else {
                HashSet::new()
            };
            batch_permissions.push(PERMS.iter().map(|&perm| apk_perms.contains(perm) as u8).collect::<Vec<_>>())
        }

        let opcodes_max_len = batch_opcodes.iter().map(|v| v.len()).max().unwrap();
        for opcodes in &mut batch_opcodes {
            opcodes.resize(opcodes_max_len, 0);
        }

        let indices_max_len = batch_indices.iter().map(|v| v.len()).max().unwrap();
        for indices in &mut batch_indices {
            indices.resize(indices_max_len, 0);
        }

        let opcodes_flat = batch_opcodes.into_iter().flatten().collect::<Vec<_>>();
        let indices_flat = batch_indices.into_iter().flatten().collect::<Vec<_>>();
        let permissions_flat = batch_permissions.into_iter().flatten().collect::<Vec<_>>();

        let opcodes = Tensor::new(&[batch_size, opcodes_max_len as u64]).with_values(&opcodes_flat).context("Can't create opcodes tensor")?;
        let indices = Tensor::new(&[batch_size, indices_max_len as u64 / 2, 2]).with_values(&indices_flat).context("Can't create indices tensor")?;
        let permissions = Tensor::new(&[batch_size, 50]).with_values(&permissions_flat).context("Can't create permissions tensor")?;

        let mut args = SessionRunArgs::new();
        args.add_feed(&opcode_sequence_in_op, 0, &opcodes);
        args.add_feed(&method_indices_in_op, 0, &indices);
        args.add_feed(&permissions_in_op, 0, &permissions);

        let output_token = args.request_fetch(&output_op, 0);
        self.bundle.session.run(&mut args).context("Can't run session")?;
        let out_res: Tensor<f32> = args.fetch(output_token).unwrap();

        Ok(out_res.array_chunks::<5>().map(|chunk| {
            let (idx, proba) = chunk.iter().enumerate().max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap()).unwrap();
            Prediction {
                detection: Detection::try_from(idx).unwrap(),
                probability: *proba,
            }
        }).collect())

    }
}
