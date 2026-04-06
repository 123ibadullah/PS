/**
 * Centralized error handling middleware for PhishShield API
 */

import { Request, Response, NextFunction } from 'express';
import { logger } from '../lib/logger.js';

export class AppError extends Error {
    constructor(
        public statusCode: number,
        public message: string,
        public errorCode?: string,
        public isOperational: boolean = true
    ) {
        super(message);
        this.name = 'AppError';

        // Capture stack trace
        Error.captureStackTrace(this, this.constructor);
    }
}

export class ValidationError extends AppError {
    constructor(message: string, details?: any) {
        super(400, message, 'VALIDATION_ERROR');
        this.name = 'ValidationError';
        if (details) {
            (this as any).details = details;
        }
    }
}

export class AuthenticationError extends AppError {
    constructor(message: string = 'Authentication required') {
        super(401, message, 'AUTHENTICATION_ERROR');
        this.name = 'AuthenticationError';
    }
}

export class AuthorizationError extends AppError {
    constructor(message: string = 'Insufficient permissions') {
        super(403, message, 'AUTHORIZATION_ERROR');
        this.name = 'AuthorizationError';
    }
}

export class NotFoundError extends AppError {
    constructor(resource: string = 'Resource') {
        super(404, `${resource} not found`, 'NOT_FOUND');
        this.name = 'NotFoundError';
    }
}

export class RateLimitError extends AppError {
    constructor(message: string = 'Too many requests') {
        super(429, message, 'RATE_LIMIT_EXCEEDED');
        this.name = 'RateLimitError';
    }
}

export class InternalServerError extends AppError {
    constructor(message: string = 'Internal server error') {
        super(500, message, 'INTERNAL_SERVER_ERROR');
        this.name = 'InternalServerError';
        this.isOperational = false;
    }
}

// Request validation error handler
export const handleValidationError = (error: any) => {
    if (error.name === 'ZodError') {
        return new ValidationError(
            'Request validation failed',
            error.errors.map((err: any) => ({
                path: err.path.join('.'),
                message: err.message,
            }))
        );
    }
    return error;
};

// Global error handler middleware
export const errorHandler = (
    error: Error | AppError,
    req: Request,
    res: Response,
    next: NextFunction
) => {
    // Generate correlation ID from request or create new
    const correlationId = (req as any).correlationId || `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // Handle validation errors
    const processedError = handleValidationError(error);

    let statusCode = 500;
    let errorCode = 'INTERNAL_SERVER_ERROR';
    let message = 'An unexpected error occurred';
    let details: any = undefined;
    let isOperational = false;

    if (processedError instanceof AppError) {
        statusCode = processedError.statusCode;
        errorCode = processedError.errorCode || 'APP_ERROR';
        message = processedError.message;
        isOperational = processedError.isOperational;

        if ((processedError as any).details) {
            details = (processedError as any).details;
        }
    } else if (processedError.name === 'SyntaxError' && 'body' in processedError) {
        // JSON parse error
        statusCode = 400;
        errorCode = 'INVALID_JSON';
        message = 'Invalid JSON payload';
        isOperational = true;
    }

    // Log the error
    const logMessage = `Request failed: ${req.method} ${req.originalUrl}`;
    const logMetadata = {
      correlationId,
      userId: (req as any).userId,
      statusCode,
      errorCode,
      method: req.method,
      url: req.originalUrl,
      userAgent: req.get('user-agent'),
      ip: req.ip,
    };
  
    if (statusCode >= 500) {
      logger.error(logMessage, processedError, logMetadata, correlationId);
    } else {
      logger.warn(logMessage, logMetadata, correlationId);
    }

    // Prepare error response
    const errorResponse: any = {
        error: {
            code: errorCode,
            message,
            correlationId,
            timestamp: new Date().toISOString(),
        },
    };

    // Include details for validation errors
    if (details) {
        errorResponse.error.details = details;
    }

    // Include stack trace in development
    if (process.env.NODE_ENV === 'development' && !isOperational) {
        errorResponse.error.stack = processedError.stack;
    }

    // Send response
    res.status(statusCode).json(errorResponse);
};

// 404 handler middleware
export const notFoundHandler = (req: Request, res: Response, next: NextFunction) => {
    const error = new NotFoundError(`Route ${req.method} ${req.originalUrl}`);
    next(error);
};

// Async handler wrapper to catch async errors
export const asyncHandler = (fn: Function) => {
    return (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// Request logging middleware
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    const correlationId = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // Store correlation ID in request for later use
    (req as any).correlationId = correlationId;

    // Log request start
    logger.debug(`Request started: ${req.method} ${req.originalUrl}`, {
        correlationId,
        method: req.method,
        url: req.originalUrl,
        query: req.query,
        body: req.body && Object.keys(req.body).length > 0 ? '***' : undefined,
        userAgent: req.get('user-agent'),
        ip: req.ip,
    }, correlationId);

    // Hook into response finish to log completion
    res.on('finish', () => {
        const durationMs = Date.now() - startTime;

        logger.logRequest(
            req.method,
            req.originalUrl,
            res.statusCode,
            durationMs,
            correlationId,
            (req as any).userId,
            {
                contentLength: res.get('content-length'),
                contentType: res.get('content-type'),
            }
        );
    });

    next();
};