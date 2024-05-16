import React, { useState } from 'react';
import './App.css';

const API = 'http://localhost:8000';

const App = () => {
    const [files, setFiles] = useState([]);
    const [results, setResults] = useState([]);
    const [hash, setHash] = useState('');
    const [error, setError] = useState('');

    const handleFileChange = (e) => {
        setFiles([...e.target.files]);
    };

    const handleUpload = async () => {
        const formData = new FormData();
        for (const file of files) {
            formData.append(file.name, file);
        }

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
                setResults(result.success);
            } else {
                setError(result.error);
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const handleHashChange = (e) => {
        setHash(e.target.value);
    };

    const handleHashSubmit = async () => {
        try {
            const response = await fetch(`${API}/query/${hash}`);

            if (!response.ok) {
                throw new Error('Failed to fetch scan result');
            }

            const result = await response.json();
            console.log(result);
            if (result.success) {
                setResults([result.success]);  // Wrap single result in an array
            } else {
                setError(result.error);
            }
        } catch (err) {
            setError(err.message);
        }
    };

    const capitalize = (word) => word.charAt(0).toUpperCase() + word.slice(1);

    const getTextColor = (detection) => {
        switch (detection) {
            case 'benign':
                return 'green';
            case 'riskware':
                return 'yellow';
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
            <h1>APK Scanner 9000</h1>
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
            {error && <p className="error">{error}</p>}
            {results.length > 0 && (
                <div className="results-section">
                    <h3>Scan Results:</h3>
                    <ul>
                        {results.map((result, index) => (
                            <li key={index}>
                                <div className="result">
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
