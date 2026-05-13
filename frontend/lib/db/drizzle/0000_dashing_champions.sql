CREATE TABLE `feedback` (
	`id` text PRIMARY KEY NOT NULL,
	`email_id` text NOT NULL,
	`is_accurate` integer NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `scan_history` (
	`id` text PRIMARY KEY NOT NULL,
	`timestamp` text NOT NULL,
	`email_preview` text NOT NULL,
	`risk_score` integer NOT NULL,
	`classification` text NOT NULL,
	`detected_language` text NOT NULL,
	`url_count` integer NOT NULL,
	`reason_count` integer NOT NULL
);
