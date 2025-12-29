CREATE TABLE `audit_logs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer,
	`username` text NOT NULL,
	`action` text NOT NULL,
	`entity_type` text NOT NULL,
	`entity_id` text,
	`entity_name` text,
	`environment_id` integer,
	`description` text,
	`details` text,
	`ip_address` text,
	`user_agent` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `audit_logs_user_id_idx` ON `audit_logs` (`user_id`);--> statement-breakpoint
CREATE INDEX `audit_logs_created_at_idx` ON `audit_logs` (`created_at`);--> statement-breakpoint
CREATE TABLE `auth_settings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`auth_enabled` integer DEFAULT false,
	`default_provider` text DEFAULT 'local',
	`session_timeout` integer DEFAULT 86400,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `auto_update_settings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`environment_id` integer,
	`container_name` text NOT NULL,
	`enabled` integer DEFAULT false,
	`schedule_type` text DEFAULT 'daily',
	`cron_expression` text,
	`vulnerability_criteria` text DEFAULT 'never',
	`last_checked` text,
	`last_updated` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `auto_update_settings_environment_id_container_name_unique` ON `auto_update_settings` (`environment_id`,`container_name`);--> statement-breakpoint
CREATE TABLE `config_sets` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`description` text,
	`env_vars` text,
	`labels` text,
	`ports` text,
	`volumes` text,
	`network_mode` text DEFAULT 'bridge',
	`restart_policy` text DEFAULT 'no',
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE UNIQUE INDEX `config_sets_name_unique` ON `config_sets` (`name`);--> statement-breakpoint
CREATE TABLE `container_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`environment_id` integer,
	`container_id` text NOT NULL,
	`container_name` text,
	`image` text,
	`action` text NOT NULL,
	`actor_attributes` text,
	`timestamp` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `container_events_env_timestamp_idx` ON `container_events` (`environment_id`,`timestamp`);--> statement-breakpoint
CREATE TABLE `environment_notifications` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`environment_id` integer NOT NULL,
	`notification_id` integer NOT NULL,
	`enabled` integer DEFAULT true,
	`event_types` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`notification_id`) REFERENCES `notification_settings`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `environment_notifications_environment_id_notification_id_unique` ON `environment_notifications` (`environment_id`,`notification_id`);--> statement-breakpoint
CREATE TABLE `environments` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`host` text,
	`port` integer DEFAULT 2375,
	`protocol` text DEFAULT 'http',
	`tls_ca` text,
	`tls_cert` text,
	`tls_key` text,
	`tls_skip_verify` integer DEFAULT false,
	`icon` text DEFAULT 'globe',
	`collect_activity` integer DEFAULT true,
	`collect_metrics` integer DEFAULT true,
	`highlight_changes` integer DEFAULT true,
	`labels` text,
	`connection_type` text DEFAULT 'socket',
	`socket_path` text DEFAULT '/var/run/docker.sock',
	`hawser_token` text,
	`hawser_last_seen` text,
	`hawser_agent_id` text,
	`hawser_agent_name` text,
	`hawser_version` text,
	`hawser_capabilities` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE UNIQUE INDEX `environments_name_unique` ON `environments` (`name`);--> statement-breakpoint
CREATE TABLE `git_credentials` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`auth_type` text DEFAULT 'none' NOT NULL,
	`username` text,
	`password` text,
	`ssh_private_key` text,
	`ssh_passphrase` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE UNIQUE INDEX `git_credentials_name_unique` ON `git_credentials` (`name`);--> statement-breakpoint
CREATE TABLE `git_repositories` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`url` text NOT NULL,
	`branch` text DEFAULT 'main',
	`credential_id` integer,
	`compose_path` text DEFAULT 'docker-compose.yml',
	`environment_id` integer,
	`auto_update` integer DEFAULT false,
	`auto_update_schedule` text DEFAULT 'daily',
	`auto_update_cron` text DEFAULT '0 3 * * *',
	`webhook_enabled` integer DEFAULT false,
	`webhook_secret` text,
	`last_sync` text,
	`last_commit` text,
	`sync_status` text DEFAULT 'pending',
	`sync_error` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`credential_id`) REFERENCES `git_credentials`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `git_repositories_name_unique` ON `git_repositories` (`name`);--> statement-breakpoint
CREATE TABLE `git_stacks` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`stack_name` text NOT NULL,
	`environment_id` integer,
	`repository_id` integer NOT NULL,
	`compose_path` text DEFAULT 'docker-compose.yml',
	`auto_update` integer DEFAULT false,
	`auto_update_schedule` text DEFAULT 'daily',
	`auto_update_cron` text DEFAULT '0 3 * * *',
	`webhook_enabled` integer DEFAULT false,
	`webhook_secret` text,
	`last_sync` text,
	`last_commit` text,
	`sync_status` text DEFAULT 'pending',
	`sync_error` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`repository_id`) REFERENCES `git_repositories`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `git_stacks_stack_name_environment_id_unique` ON `git_stacks` (`stack_name`,`environment_id`);--> statement-breakpoint
CREATE TABLE `hawser_tokens` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`token` text NOT NULL,
	`token_prefix` text NOT NULL,
	`name` text NOT NULL,
	`environment_id` integer,
	`is_active` integer DEFAULT true,
	`last_used` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`expires_at` text,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `hawser_tokens_token_unique` ON `hawser_tokens` (`token`);--> statement-breakpoint
CREATE TABLE `host_metrics` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`environment_id` integer,
	`cpu_percent` real NOT NULL,
	`memory_percent` real NOT NULL,
	`memory_used` integer,
	`memory_total` integer,
	`timestamp` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `host_metrics_env_timestamp_idx` ON `host_metrics` (`environment_id`,`timestamp`);--> statement-breakpoint
CREATE TABLE `ldap_config` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`enabled` integer DEFAULT false,
	`server_url` text NOT NULL,
	`bind_dn` text,
	`bind_password` text,
	`base_dn` text NOT NULL,
	`user_filter` text DEFAULT '(uid={{username}})',
	`username_attribute` text DEFAULT 'uid',
	`email_attribute` text DEFAULT 'mail',
	`display_name_attribute` text DEFAULT 'cn',
	`group_base_dn` text,
	`group_filter` text,
	`admin_group` text,
	`role_mappings` text,
	`tls_enabled` integer DEFAULT false,
	`tls_ca` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `notification_settings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`type` text NOT NULL,
	`name` text NOT NULL,
	`enabled` integer DEFAULT true,
	`config` text NOT NULL,
	`event_types` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `oidc_config` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`enabled` integer DEFAULT false,
	`issuer_url` text NOT NULL,
	`client_id` text NOT NULL,
	`client_secret` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`scopes` text DEFAULT 'openid profile email',
	`username_claim` text DEFAULT 'preferred_username',
	`email_claim` text DEFAULT 'email',
	`display_name_claim` text DEFAULT 'name',
	`admin_claim` text,
	`admin_value` text,
	`role_mappings_claim` text DEFAULT 'groups',
	`role_mappings` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `registries` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`url` text NOT NULL,
	`username` text,
	`password` text,
	`is_default` integer DEFAULT false,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE UNIQUE INDEX `registries_name_unique` ON `registries` (`name`);--> statement-breakpoint
CREATE TABLE `roles` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`description` text,
	`is_system` integer DEFAULT false,
	`permissions` text NOT NULL,
	`environment_ids` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE UNIQUE INDEX `roles_name_unique` ON `roles` (`name`);--> statement-breakpoint
CREATE TABLE `schedule_executions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`schedule_type` text NOT NULL,
	`schedule_id` integer NOT NULL,
	`environment_id` integer,
	`entity_name` text NOT NULL,
	`triggered_by` text NOT NULL,
	`triggered_at` text NOT NULL,
	`started_at` text,
	`completed_at` text,
	`duration` integer,
	`status` text NOT NULL,
	`error_message` text,
	`details` text,
	`logs` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `schedule_executions_type_id_idx` ON `schedule_executions` (`schedule_type`,`schedule_id`);--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` integer NOT NULL,
	`provider` text NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sessions_user_id_idx` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `sessions_expires_at_idx` ON `sessions` (`expires_at`);--> statement-breakpoint
CREATE TABLE `settings` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE TABLE `stack_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`environment_id` integer,
	`stack_name` text NOT NULL,
	`event_type` text NOT NULL,
	`timestamp` text DEFAULT CURRENT_TIMESTAMP,
	`metadata` text,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `stack_sources` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`stack_name` text NOT NULL,
	`environment_id` integer,
	`source_type` text DEFAULT 'internal' NOT NULL,
	`git_repository_id` integer,
	`git_stack_id` integer,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`git_repository_id`) REFERENCES `git_repositories`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`git_stack_id`) REFERENCES `git_stacks`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `stack_sources_stack_name_environment_id_unique` ON `stack_sources` (`stack_name`,`environment_id`);--> statement-breakpoint
CREATE TABLE `user_preferences` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer,
	`environment_id` integer,
	`key` text NOT NULL,
	`value` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_preferences_user_id_environment_id_key_unique` ON `user_preferences` (`user_id`,`environment_id`,`key`);--> statement-breakpoint
CREATE TABLE `user_roles` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`role_id` integer NOT NULL,
	`environment_id` integer,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_roles_user_id_role_id_environment_id_unique` ON `user_roles` (`user_id`,`role_id`,`environment_id`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`username` text NOT NULL,
	`email` text,
	`password_hash` text NOT NULL,
	`display_name` text,
	`avatar` text,
	`auth_provider` text DEFAULT 'local',
	`mfa_enabled` integer DEFAULT false,
	`mfa_secret` text,
	`is_active` integer DEFAULT true,
	`last_login` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_username_unique` ON `users` (`username`);--> statement-breakpoint
CREATE TABLE `vulnerability_scans` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`environment_id` integer,
	`image_id` text NOT NULL,
	`image_name` text NOT NULL,
	`scanner` text NOT NULL,
	`scanned_at` text NOT NULL,
	`scan_duration` integer,
	`critical_count` integer DEFAULT 0,
	`high_count` integer DEFAULT 0,
	`medium_count` integer DEFAULT 0,
	`low_count` integer DEFAULT 0,
	`negligible_count` integer DEFAULT 0,
	`unknown_count` integer DEFAULT 0,
	`vulnerabilities` text,
	`error` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `vulnerability_scans_env_image_idx` ON `vulnerability_scans` (`environment_id`,`image_id`);