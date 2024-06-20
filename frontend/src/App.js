import React, { useState } from 'react';
import HashLoader from 'react-spinners/HashLoader';
import './App.css';

const API = 'http://localhost:8000';

const App = () => {
    const [files, setFiles] = useState([]);
    const [fileMap, setFileMap] = useState({});
    const [results, setResults] = useState([]);
    const [hash, setHash] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleFileChange = async (e) => {
        const selectedFiles = [...e.target.files];
        setFiles(selectedFiles);
        const newFileMap = {};
        for (const file of selectedFiles) {
            const arrayBuffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
            newFileMap[hashHex] = file.name;
        }
        setFileMap(newFileMap);
    };

    const handleUpload = async () => {
        const formData = new FormData();
        for (const file of files) {
            formData.append(file.name, file);
        }

        setLoading(true);
        setResults([]);
        setError('');

        try {
            const response = await fetch(`${API}/scan`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Failed to upload files');
            }

            const result = await response.json();
            if (result.success) {
                const new_results = result.success.map((res) => ({
                    filename: fileMap.hasOwnProperty(res.sha256) ? fileMap[res.sha256] : '',
                    sha256: res.sha256,
                    prediction: res.prediction
                }))
                new_results.sort((a, b) => a.filename.localeCompare(b.filename));
                setResults(new_results);
            } else {
                setError(result.error);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleHashChange = (e) => {
        setHash(e.target.value);
    };

    const handleHashSubmit = async () => {
        setLoading(true);
        setResults([]);
        setError('');

        try {
            const response = await fetch(`${API}/query/${hash}`);

            if (!response.ok) {
                if (response.status === 404) {
                    setError('File not found')
                } else {
                    throw new Error('Failed to fetch scan result');
                }
            }

            const result = await response.json();
            if (result.success) {
                setResults([result.success]);
                setFileMap({});
            } else {
                setError(result.error);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const capitalize = (word) => word.charAt(0).toUpperCase() + word.slice(1);

    const getTextColor = (detection) => {
        switch (detection) {
            case 'benign':
                return 'green';
            case 'riskware':
                return 'orange';
            default:
                return 'red';
        }
    };

    const formatProbability = (proba) => {
        const formatted = proba.toFixed(3);
        return formatted.slice(0, formatted.indexOf('.') + 3);
    };

    return (
        <div className="container">
            <h1>APK Scanner</h1>
            <div className="upload-section">
                <h2>Upload Files for Scanning</h2>
                <input type="file" multiple onChange={handleFileChange} />
                <button onClick={handleUpload}>Upload</button>
            </div>
            <div className="hash-section">
                <h2>Check File by SHA-256</h2>
                <input type="text" value={hash} onChange={handleHashChange} placeholder="Enter SHA-256 hash" />
                <button onClick={handleHashSubmit}>Check</button>
            </div>
            {loading && (
                <div className="spinner-container">
                    <HashLoader color="#3498db" />
                </div>
            )}
            {error && <p className="error">{error}</p>}
            {results.length > 0 && (
                <div className="results-section">
                    <h3>Scan Results:</h3>
                    <ul>
                        {results.map((result, index) => (
                            <li key={index}>
                                <div className="result">
                                    {result.filename ? <p><strong>Filename:</strong> {result.filename}</p> : null}
                                    <p><strong>SHA256:</strong> {result.sha256}</p>
                                    <p style={{ color: getTextColor(result.prediction.det) }}>
                                        <strong>Detection:</strong> {capitalize(result.prediction.det)}
                                    </p>
                                    <p><strong>Probability:</strong> {formatProbability(result.prediction.proba)}</p>
                                </div>
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
};

export default App;
