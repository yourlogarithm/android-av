import keras
import tensorflow as tf

class Attention(keras.layers.Layer):
    def __init__(self, latent_dim, latent_length, num_heads):
        super(Attention, self).__init__()
        self._multihead = keras.layers.MultiHeadAttention(num_heads=num_heads, key_dim=latent_length)
        self._norm = keras.layers.LayerNormalization()
        self._mlp = keras.Sequential([
            keras.layers.Dense(latent_dim, activation='gelu'),
            keras.layers.Dropout(0.1),
            keras.layers.Dense(latent_dim, activation='gelu'),
            keras.layers.Dropout(0.1),
        ])
        
    def mlp(self, latent_state, x):
        x = self._norm(latent_state + x)
        return self._norm(x + self._mlp(x))
        
class CrossAttention(Attention):
    def __init__(self, latent_dim, latent_length):
        super(CrossAttention, self).__init__(latent_dim, latent_length, 1)

    def call(self, latent_state, input_seq):
        norm_input_seq = self._norm(input_seq)
        x = self._multihead(query=self._norm(latent_state), value=norm_input_seq, key=norm_input_seq)
        return self.mlp(latent_state, x)

class SelfAttention(Attention):
    def __init__(self, latent_dim, latent_length):
        super(SelfAttention, self).__init__(latent_dim, latent_length, 2)

    def call(self, latent_state):
        norm_latent_state = self._norm(latent_state)
        x = self._multihead(query=norm_latent_state, value=norm_latent_state, key=norm_latent_state)
        return self.mlp(latent_state, x)

class PerceiverIO(keras.layers.Layer):
    def __init__(self, *, latent_dim, latent_length, name=None):
        super(PerceiverIO, self).__init__(name=name)
        self._cross = CrossAttention(latent_dim, latent_length)
        self._self = [
            SelfAttention(latent_dim, latent_length) 
            for _ in range(2)
        ]
    
    def call(self, latent_state, input_seq):
        x = self._cross(latent_state, input_seq)
        for block in self._self:
            x = block(x)
        return x
    
class MethodFeatures(keras.layers.Layer):
    def __init__(self, name=None):
        super(MethodFeatures, self).__init__(name=name)
    
    def call(self, opcode_filters, method_indices):
        cumsum = tf.cumsum(opcode_filters, axis=1)
        sequence_length = tf.shape(opcode_filters)[1] - 1
        start_indices = tf.clip_by_value(method_indices[:, :, 0], 0, sequence_length)
        end_indices = tf.clip_by_value(method_indices[:, :, 1], 0, sequence_length)
        start_sum = tf.gather(cumsum, start_indices, batch_dims=1, axis=1)
        end_sum = tf.gather(cumsum, end_indices, batch_dims=1, axis=1)
        method_lengths = end_indices - start_indices + 1
        return (end_sum - start_sum) / tf.cast(method_lengths[..., tf.newaxis], tf.float32)
    
def get_model(latent_length=32, hidden_dim=16, n_perms=50, n_categories=5):
    opcode_sequence_input = keras.layers.Input(shape=(None,), dtype=tf.uint8, name='opcode_sequence_in')
    method_indices_input = keras.layers.Input(shape=(None, 2), dtype=tf.int32, name='method_indices_in')
    permissions_input = keras.layers.Input(shape=(n_perms,), dtype=tf.uint8, name='permissions_in')

    embedding = keras.layers.Embedding(input_dim=256, output_dim=hidden_dim, name='opcode_embedding')(opcode_sequence_input)
    filters = keras.layers.Conv1D(hidden_dim, kernel_size=3, activation='relu', name='convolutional_filters')(embedding)

    latent_state = tf.Variable(tf.random.normal([1, latent_length, hidden_dim]))

    # Opcode modality
    latent_state = PerceiverIO(latent_dim=hidden_dim, latent_length=latent_length, name='local_perceiver')(latent_state, filters)

    # Method modality
    method_features = MethodFeatures(name='method_features')(filters, method_indices_input)
    latent_state = PerceiverIO(latent_dim=hidden_dim, latent_length=latent_length, name='methods_perceiver')(latent_state, method_features)

    # Global modality
    global_features = keras.layers.GlobalMaxPooling1D(keepdims=True)(filters)
    latent_state = PerceiverIO(latent_dim=hidden_dim, latent_length=latent_length, name='global_perceiver')(latent_state, global_features)

    # Permissions
    permissions_hidden = keras.layers.Dense((n_perms + hidden_dim) // 2, activation='relu', name='permissions_hidden_layer')(permissions_input)
    permissions_logits = keras.layers.Dense(hidden_dim // 2, activation='relu', name='permissions_logits')(permissions_hidden)

    pooling = keras.layers.GlobalAveragePooling1D(name='global_pooling')(latent_state)
    joined = keras.layers.Concatenate(name='concatenation_layer')([pooling, permissions_logits])
    
    classifier = keras.layers.Dense(len(categories), activation='softmax')(joined)
    model = keras.models.Model(inputs=[opcode_sequence_input, method_indices_input, permissions_input], outputs=classifier)
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    
    return model
