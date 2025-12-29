CREATE TABLE `stack_environment_variables` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`stack_name` text NOT NULL,
	`environment_id` integer,
	`key` text NOT NULL,
	`value` text NOT NULL,
	`is_secret` integer DEFAULT false,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `stack_environment_variables_stack_name_environment_id_key_unique` ON `stack_environment_variables` (`stack_name`,`environment_id`,`key`);--> statement-breakpoint
ALTER TABLE `git_stacks` ADD `env_file_path` text;