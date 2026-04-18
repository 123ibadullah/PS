/**
 * Structured logging utility for PhishShield API
 * Provides consistent logging with different levels and structured output
 */

export type LogLevel = 'error' | 'warn' | 'info' | 'debug';

export interface LogEntry {
    timestamp: string;
    level: LogLevel;
    message: string;
    service: string;
    correlationId?: string;
    userId?: string;
    requestId?: string;
    durationMs?: number;
    error?: {
        name: string;
        message: string;
        stack?: string;
        code?: string;
    };
    metadata?: Record<string, any>;
}

class Logger {
    private service: string;
    private minLevel: LogLevel;

    constructor(service: string = 'api-server', minLevel: LogLevel = 'info') {
        this.service = service;
        this.minLevel = minLevel;
    }

    private shouldLog(level: LogLevel): boolean {
        const levels: Record<LogLevel, number> = {
            error: 4,
            warn: 3,
            info: 2,
            debug: 1,
        };
        return levels[level] >= levels[this.minLevel];
    }

    private formatLog(entry: Omit<LogEntry, 'timestamp' | 'service'>): LogEntry {
        const fullEntry: LogEntry = {
            timestamp: new Date().toISOString(),
            service: this.service,
            ...entry,
        };

        // Output to console with appropriate styling
        const levelColors: Record<LogLevel, string> = {
            error: '\x1b[31m', // Red
            warn: '\x1b[33m',  // Yellow
            info: '\x1b[36m',  // Cyan
            debug: '\x1b[90m', // Gray
        };

        const reset = '\x1b[0m';
        const level = entry.level.toUpperCase();
        const color = levelColors[entry.level] || reset;

        const baseMessage = `${fullEntry.timestamp} [${level}] ${entry.message}`;
        const context = entry.correlationId ? `[corr:${entry.correlationId}]` : '';

        console.log(`${color}${baseMessage}${context}${reset}`);

        if (entry.error) {
            console.error(`${color}Error: ${entry.error.name}: ${entry.error.message}${reset}`);
            if (entry.error.stack && this.minLevel === 'debug') {
                console.error(`${color}Stack: ${entry.error.stack}${reset}`);
            }
        }

        if (entry.metadata && Object.keys(entry.metadata).length > 0 && this.minLevel === 'debug') {
            console.log(`${color}Metadata: ${JSON.stringify(entry.metadata, null, 2)}${reset}`);
        }

        return fullEntry;
    }

    error(message: string, error?: Error, metadata?: Record<string, any>, correlationId?: string) {
        if (!this.shouldLog('error')) return;

        const logEntry: Omit<LogEntry, 'timestamp' | 'service'> = {
            level: 'error',
            message,
            correlationId,
            error: error ? {
                name: error.name,
                message: error.message,
                stack: error.stack,
            } : undefined,
            metadata,
        };

        return this.formatLog(logEntry);
    }

    warn(message: string, metadata?: Record<string, any>, correlationId?: string) {
        if (!this.shouldLog('warn')) return;

        const logEntry: Omit<LogEntry, 'timestamp' | 'service'> = {
            level: 'warn',
            message,
            correlationId,
            metadata,
        };

        return this.formatLog(logEntry);
    }

    info(message: string, metadata?: Record<string, any>, correlationId?: string) {
        if (!this.shouldLog('info')) return;

        const logEntry: Omit<LogEntry, 'timestamp' | 'service'> = {
            level: 'info',
            message,
            correlationId,
            metadata,
        };

        return this.formatLog(logEntry);
    }

    debug(message: string, metadata?: Record<string, any>, correlationId?: string) {
        if (!this.shouldLog('debug')) return;

        const logEntry: Omit<LogEntry, 'timestamp' | 'service'> = {
            level: 'debug',
            message,
            correlationId,
            metadata,
        };

        return this.formatLog(logEntry);
    }

    // Request/response logging helper
    logRequest(
        method: string,
        url: string,
        statusCode: number,
        durationMs: number,
        correlationId?: string,
        userId?: string,
        metadata?: Record<string, any>
    ) {
        const level = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'info';

        const logEntry: Omit<LogEntry, 'timestamp' | 'service'> = {
            level,
            message: `${method} ${url} ${statusCode} ${durationMs}ms`,
            correlationId,
            userId,
            durationMs,
            metadata: {
                method,
                url,
                statusCode,
                durationMs,
                ...metadata,
            },
        };

        return this.formatLog(logEntry);
    }
}

// Create default logger instance
export const logger = new Logger('phishshield-api',
    process.env.NODE_ENV === 'development' ? 'debug' : 'info'
);

// Domain-specific loggers
export const phishingLogger = new Logger('phishing-detector', 'info');
export const authLogger = new Logger('auth', 'warn');
export const dbLogger = new Logger('database', 'warn');