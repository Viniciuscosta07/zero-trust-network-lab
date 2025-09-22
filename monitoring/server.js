#!/usr/bin/env node
/**
 * Zero Trust Network Monitoring Dashboard
 * 
 * This Node.js server provides a comprehensive web-based monitoring interface
 * for the zero trust network implementation, including real-time analytics,
 * security event monitoring, and system health visualization.
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Configuration
const PORT = process.env.PORT || 8080;
const INTEGRATION_API_URL = process.env.INTEGRATION_API_URL || 'http://integration-api:8006';

// Middleware
app.use(helmet({
    contentSecurityPolicy: false // Allow inline scripts for dashboard
}));
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Logging
const winston = require('winston');
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: '/app/logs/dashboard.log' }),
        new winston.transports.Console()
    ]
});

// Data aggregation service
class DataAggregator {
    constructor() {
        this.systemStatus = {};
        this.realtimeMetrics = {
            activeConnections: 0,
            authenticationRate: 0,
            policyViolations: 0,
            complianceRate: 0
        };
        this.eventHistory = [];
        this.startDataCollection();
    }

    startDataCollection() {
        // Collect system status every 30 seconds
        setInterval(() => {
            this.collectSystemStatus();
        }, 30000);

        // Collect real-time metrics every 5 seconds
        setInterval(() => {
            this.collectRealtimeMetrics();
        }, 5000);

        // Collect events every 10 seconds
        setInterval(() => {
            this.collectEvents();
        }, 10000);

        logger.info('Data collection started');
    }

    async collectSystemStatus() {
        try {
            const response = await axios.get(`${INTEGRATION_API_URL}/api/system/status`, {
                timeout: 5000
            });
            
            this.systemStatus = response.data;
            
            // Broadcast to connected clients
            io.emit('systemStatus', this.systemStatus);
            
        } catch (error) {
            logger.error('Failed to collect system status:', error.message);
            this.systemStatus = {
                overall_status: 'error',
                error: 'Unable to connect to integration API',
                timestamp: new Date().toISOString()
            };
        }
    }

    async collectRealtimeMetrics() {
        try {
            // In a real implementation, these would come from various services
            // For demo purposes, we'll simulate some realistic data
            
            const baseConnections = 50;
            const variance = Math.random() * 20 - 10;
            this.realtimeMetrics.activeConnections = Math.max(0, baseConnections + variance);
            
            this.realtimeMetrics.authenticationRate = Math.floor(Math.random() * 10);
            this.realtimeMetrics.policyViolations = Math.floor(Math.random() * 5);
            this.realtimeMetrics.complianceRate = 85 + Math.random() * 10;
            
            // Broadcast to connected clients
            io.emit('realtimeMetrics', this.realtimeMetrics);
            
        } catch (error) {
            logger.error('Failed to collect realtime metrics:', error.message);
        }
    }

    async collectEvents() {
        try {
            const response = await axios.get(`${INTEGRATION_API_URL}/api/events?hours=1`, {
                timeout: 5000
            });
            
            const newEvents = response.data.events || [];
            
            // Keep only recent events (last 100)
            this.eventHistory = [...newEvents, ...this.eventHistory].slice(0, 100);
            
            // Broadcast new events to connected clients
            if (newEvents.length > 0) {
                io.emit('newEvents', newEvents);
            }
            
        } catch (error) {
            logger.error('Failed to collect events:', error.message);
        }
    }

    getSystemStatus() {
        return this.systemStatus;
    }

    getRealtimeMetrics() {
        return this.realtimeMetrics;
    }

    getEventHistory() {
        return this.eventHistory;
    }
}

// Initialize data aggregator
const dataAggregator = new DataAggregator();

// API Routes
app.get('/api/dashboard/status', (req, res) => {
    res.json({
        status: 'operational',
        systemStatus: dataAggregator.getSystemStatus(),
        realtimeMetrics: dataAggregator.getRealtimeMetrics(),
        timestamp: new Date().toISOString()
    });
});

app.get('/api/dashboard/events', (req, res) => {
    const events = dataAggregator.getEventHistory();
    res.json({
        events: events,
        count: events.length
    });
});

app.get('/api/dashboard/metrics', (req, res) => {
    res.json(dataAggregator.getRealtimeMetrics());
});

// Proxy requests to integration API
app.use('/api/integration', async (req, res) => {
    try {
        const targetUrl = `${INTEGRATION_API_URL}${req.path}`;
        
        const response = await axios({
            method: req.method,
            url: targetUrl,
            data: req.body,
            headers: {
                'Content-Type': 'application/json',
                ...req.headers
            },
            timeout: 10000
        });
        
        res.status(response.status).json(response.data);
        
    } catch (error) {
        logger.error('Proxy request failed:', error.message);
        res.status(500).json({
            error: 'Integration API unavailable',
            message: error.message
        });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'monitoring-dashboard',
        timestamp: new Date().toISOString()
    });
});

// Serve main dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    logger.info('Client connected to dashboard');
    
    // Send current data to new client
    socket.emit('systemStatus', dataAggregator.getSystemStatus());
    socket.emit('realtimeMetrics', dataAggregator.getRealtimeMetrics());
    socket.emit('eventHistory', dataAggregator.getEventHistory());
    
    socket.on('disconnect', () => {
        logger.info('Client disconnected from dashboard');
    });
    
    // Handle client requests
    socket.on('requestSystemRefresh', () => {
        dataAggregator.collectSystemStatus();
    });
    
    socket.on('requestMetricsRefresh', () => {
        dataAggregator.collectRealtimeMetrics();
    });
});

// Error handling
app.use((err, req, res, next) => {
    logger.error('Express error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
    logger.info(`Zero Trust Monitoring Dashboard started on port ${PORT}`);
    logger.info(`Dashboard URL: http://localhost:${PORT}`);
    
    // Initial data collection
    setTimeout(() => {
        dataAggregator.collectSystemStatus();
        dataAggregator.collectRealtimeMetrics();
        dataAggregator.collectEvents();
    }, 2000);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('Received SIGTERM, shutting down gracefully');
    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    logger.info('Received SIGINT, shutting down gracefully');
    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
});

module.exports = app;
