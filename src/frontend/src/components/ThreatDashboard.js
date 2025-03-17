import { Alert, Select, Spin, Table } from 'antd';
import React, { useEffect, useState } from 'react';
import { Bar, BarChart, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import './ThreatDashboard.css'; // Add custom styles if needed

const { Option } = Select;

function ThreatDashboard() {
    const [assets, setAssets] = useState([]);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [riskScores, setRiskScores] = useState([]);
    const [threatLogs, setThreatLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [filters, setFilters] = useState({
        severity: 'all',
        asset: 'all',
    });

    // Fetch data from the backend
    useEffect(() => {
        const fetchData = async () => {
            try {
                const [assetResponse, vulnerabilityResponse, riskResponse, logsResponse] = await Promise.all([
                    fetch('http://localhost:5001/api/assets'),
                    fetch('http://localhost:5001/api/vulnerabilities'),
                    fetch('http://localhost:5001/api/risk-scores'),
                    fetch('http://localhost:5001/api/threat-logs'), // New endpoint for threat logs
                ]);

                if (!assetResponse.ok || !vulnerabilityResponse.ok || !riskResponse.ok || !logsResponse.ok) {
                    throw new Error('Failed to fetch data');
                }

                const [assetData, vulnerabilityData, riskData, logsData] = await Promise.all([
                    assetResponse.json(),
                    vulnerabilityResponse.json(),
                    riskResponse.json(),
                    logsResponse.json(),
                ]);

                setAssets(assetData);
                setVulnerabilities(vulnerabilityData);
                setRiskScores(riskData);
                setThreatLogs(logsData);
            } catch (err) {
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        fetchData();

        // Polling for real-time updates (every 10 seconds)
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, []);

    // Filter data based on user selection
    const filteredThreatLogs = threatLogs.filter(log => {
        const matchesSeverity = filters.severity === 'all' || log.severity === filters.severity;
        const matchesAsset = filters.asset === 'all' || log.assetId === filters.asset;
        return matchesSeverity && matchesAsset;
    });

    const filteredRiskScores = riskScores.filter(score => {
        return filters.asset === 'all' || score.assetId === filters.asset;
    });

    if (loading) return <Spin size="large" className="loading-spinner" />;
    if (error) return <Alert message={`Error: ${error}`} type="error" />;

    return (
        <div className="p-4">
            <h1 className="text-2xl font-bold">Threat Dashboard</h1>

            {/* Filters */}
            <div className="filters mb-4">
                <Select
                    defaultValue="all"
                    style={{ width: 200, marginRight: 16 }}
                    onChange={value => setFilters({ ...filters, severity: value })}
                >
                    <Option value="all">All Severities</Option>
                    <Option value="low">Low</Option>
                    <Option value="medium">Medium</Option>
                    <Option value="high">High</Option>
                </Select>
                <Select
                    defaultValue="all"
                    style={{ width: 200 }}
                    onChange={value => setFilters({ ...filters, asset: value })}
                >
                    <Option value="all">All Assets</Option>
                    {assets.map(asset => (
                        <Option key={asset.id} value={asset.id}>
                            {asset.name}
                        </Option>
                    ))}
                </Select>
            </div>

            {/* Risk Scores Chart */}
            <div className="mb-8">
                <h2 className="text-xl font-semibold">Risk Scores</h2>
                <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={filteredRiskScores}>
                        <XAxis dataKey="name" />
                        <YAxis />
                        <Tooltip />
                        <Legend />
                        <Bar dataKey="value" fill="#8884d8" />
                    </BarChart>
                </ResponsiveContainer>
            </div>

            {/* Threat Logs Table */}
            <div className="mb-8">
                <h2 className="text-xl font-semibold">Threat Logs</h2>
                <Table
                    dataSource={filteredThreatLogs}
                    columns={[
                        { title: 'Timestamp', dataIndex: 'timestamp', key: 'timestamp' },
                        { title: 'Severity', dataIndex: 'severity', key: 'severity' },
                        { title: 'Source', dataIndex: 'source', key: 'source' },
                        { title: 'Description', dataIndex: 'description', key: 'description' },
                    ]}
                    rowKey="id"
                    pagination={{ pageSize: 5 }}
                />
            </div>

            {/* Asset Inventory */}
            <div className="mb-8">
                <h2 className="text-xl font-semibold">Asset Inventory</h2>
                <ul>
                    {assets.map(asset => (
                        <li key={asset.id} className="mb-2">
                            <strong>{asset.name}</strong> - {asset.type}
                        </li>
                    ))}
                </ul>
            </div>
        </div>
    );
}

export default ThreatDashboard;