CREATE TABLE `pending_container_updates` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`environment_id` integer NOT NULL,
	`container_id` text NOT NULL,
	`container_name` text NOT NULL,
	`current_image` text NOT NULL,
	`checked_at` text DEFAULT CURRENT_TIMESTAMP,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (`environment_id`) REFERENCES `environments`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `pending_container_updates_environment_id_container_id_unique` ON `pending_container_updates` (`environment_id`,`container_id`);