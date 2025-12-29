CREATE TABLE "audit_logs" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer,
	"username" text NOT NULL,
	"action" text NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" text,
	"entity_name" text,
	"environment_id" integer,
	"description" text,
	"details" text,
	"ip_address" text,
	"user_agent" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "auth_settings" (
	"id" serial PRIMARY KEY NOT NULL,
	"auth_enabled" boolean DEFAULT false,
	"default_provider" text DEFAULT 'local',
	"session_timeout" integer DEFAULT 86400,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "auto_update_settings" (
	"id" serial PRIMARY KEY NOT NULL,
	"environment_id" integer,
	"container_name" text NOT NULL,
	"enabled" boolean DEFAULT false,
	"schedule_type" text DEFAULT 'daily',
	"cron_expression" text,
	"vulnerability_criteria" text DEFAULT 'never',
	"last_checked" timestamp,
	"last_updated" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "auto_update_settings_environment_id_container_name_unique" UNIQUE("environment_id","container_name")
);
--> statement-breakpoint
CREATE TABLE "config_sets" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"env_vars" text,
	"labels" text,
	"ports" text,
	"volumes" text,
	"network_mode" text DEFAULT 'bridge',
	"restart_policy" text DEFAULT 'no',
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "config_sets_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "container_events" (
	"id" serial PRIMARY KEY NOT NULL,
	"environment_id" integer,
	"container_id" text NOT NULL,
	"container_name" text,
	"image" text,
	"action" text NOT NULL,
	"actor_attributes" text,
	"timestamp" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "environment_notifications" (
	"id" serial PRIMARY KEY NOT NULL,
	"environment_id" integer NOT NULL,
	"notification_id" integer NOT NULL,
	"enabled" boolean DEFAULT true,
	"event_types" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "environment_notifications_environment_id_notification_id_unique" UNIQUE("environment_id","notification_id")
);
--> statement-breakpoint
CREATE TABLE "environments" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"host" text,
	"port" integer DEFAULT 2375,
	"protocol" text DEFAULT 'http',
	"tls_ca" text,
	"tls_cert" text,
	"tls_key" text,
	"tls_skip_verify" boolean DEFAULT false,
	"icon" text DEFAULT 'globe',
	"collect_activity" boolean DEFAULT true,
	"collect_metrics" boolean DEFAULT true,
	"highlight_changes" boolean DEFAULT true,
	"labels" text,
	"connection_type" text DEFAULT 'socket',
	"socket_path" text DEFAULT '/var/run/docker.sock',
	"hawser_token" text,
	"hawser_last_seen" timestamp,
	"hawser_agent_id" text,
	"hawser_agent_name" text,
	"hawser_version" text,
	"hawser_capabilities" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "environments_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "git_credentials" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"auth_type" text DEFAULT 'none' NOT NULL,
	"username" text,
	"password" text,
	"ssh_private_key" text,
	"ssh_passphrase" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "git_credentials_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "git_repositories" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"url" text NOT NULL,
	"branch" text DEFAULT 'main',
	"credential_id" integer,
	"compose_path" text DEFAULT 'docker-compose.yml',
	"environment_id" integer,
	"auto_update" boolean DEFAULT false,
	"auto_update_schedule" text DEFAULT 'daily',
	"auto_update_cron" text DEFAULT '0 3 * * *',
	"webhook_enabled" boolean DEFAULT false,
	"webhook_secret" text,
	"last_sync" timestamp,
	"last_commit" text,
	"sync_status" text DEFAULT 'pending',
	"sync_error" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "git_repositories_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "git_stacks" (
	"id" serial PRIMARY KEY NOT NULL,
	"stack_name" text NOT NULL,
	"environment_id" integer,
	"repository_id" integer NOT NULL,
	"compose_path" text DEFAULT 'docker-compose.yml',
	"auto_update" boolean DEFAULT false,
	"auto_update_schedule" text DEFAULT 'daily',
	"auto_update_cron" text DEFAULT '0 3 * * *',
	"webhook_enabled" boolean DEFAULT false,
	"webhook_secret" text,
	"last_sync" timestamp,
	"last_commit" text,
	"sync_status" text DEFAULT 'pending',
	"sync_error" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "git_stacks_stack_name_environment_id_unique" UNIQUE("stack_name","environment_id")
);
--> statement-breakpoint
CREATE TABLE "hawser_tokens" (
	"id" serial PRIMARY KEY NOT NULL,
	"token" text NOT NULL,
	"token_prefix" text NOT NULL,
	"name" text NOT NULL,
	"environment_id" integer,
	"is_active" boolean DEFAULT true,
	"last_used" timestamp,
	"created_at" timestamp DEFAULT now(),
	"expires_at" timestamp,
	CONSTRAINT "hawser_tokens_token_unique" UNIQUE("token")
);
--> statement-breakpoint
CREATE TABLE "host_metrics" (
	"id" serial PRIMARY KEY NOT NULL,
	"environment_id" integer,
	"cpu_percent" double precision NOT NULL,
	"memory_percent" double precision NOT NULL,
	"memory_used" bigint,
	"memory_total" bigint,
	"timestamp" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "ldap_config" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"enabled" boolean DEFAULT false,
	"server_url" text NOT NULL,
	"bind_dn" text,
	"bind_password" text,
	"base_dn" text NOT NULL,
	"user_filter" text DEFAULT '(uid={{username}})',
	"username_attribute" text DEFAULT 'uid',
	"email_attribute" text DEFAULT 'mail',
	"display_name_attribute" text DEFAULT 'cn',
	"group_base_dn" text,
	"group_filter" text,
	"admin_group" text,
	"role_mappings" text,
	"tls_enabled" boolean DEFAULT false,
	"tls_ca" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "notification_settings" (
	"id" serial PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"name" text NOT NULL,
	"enabled" boolean DEFAULT true,
	"config" text NOT NULL,
	"event_types" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "oidc_config" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"enabled" boolean DEFAULT false,
	"issuer_url" text NOT NULL,
	"client_id" text NOT NULL,
	"client_secret" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"scopes" text DEFAULT 'openid profile email',
	"username_claim" text DEFAULT 'preferred_username',
	"email_claim" text DEFAULT 'email',
	"display_name_claim" text DEFAULT 'name',
	"admin_claim" text,
	"admin_value" text,
	"role_mappings_claim" text DEFAULT 'groups',
	"role_mappings" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "registries" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"url" text NOT NULL,
	"username" text,
	"password" text,
	"is_default" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "registries_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "roles" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"is_system" boolean DEFAULT false,
	"permissions" text NOT NULL,
	"environment_ids" text,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "roles_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "schedule_executions" (
	"id" serial PRIMARY KEY NOT NULL,
	"schedule_type" text NOT NULL,
	"schedule_id" integer NOT NULL,
	"environment_id" integer,
	"entity_name" text NOT NULL,
	"triggered_by" text NOT NULL,
	"triggered_at" timestamp NOT NULL,
	"started_at" timestamp,
	"completed_at" timestamp,
	"duration" integer,
	"status" text NOT NULL,
	"error_message" text,
	"details" text,
	"logs" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"provider" text NOT NULL,
	"expires_at" timestamp NOT NULL,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "settings" (
	"key" text PRIMARY KEY NOT NULL,
	"value" text NOT NULL,
	"updated_at" timestamp DEFAULT now()
);
--> statement-breakpoint
CREATE TABLE "stack_events" (
	"id" serial PRIMARY KEY NOT NULL,
	"environment_id" integer,
	"stack_name" text NOT NULL,
	"event_type" text NOT NULL,
	"timestamp" timestamp DEFAULT now(),
	"metadata" text
);
--> statement-breakpoint
CREATE TABLE "stack_sources" (
	"id" serial PRIMARY KEY NOT NULL,
	"stack_name" text NOT NULL,
	"environment_id" integer,
	"source_type" text DEFAULT 'internal' NOT NULL,
	"git_repository_id" integer,
	"git_stack_id" integer,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "stack_sources_stack_name_environment_id_unique" UNIQUE("stack_name","environment_id")
);
--> statement-breakpoint
CREATE TABLE "user_preferences" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer,
	"environment_id" integer,
	"key" text NOT NULL,
	"value" text NOT NULL,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "user_preferences_user_id_environment_id_key_unique" UNIQUE("user_id","environment_id","key")
);
--> statement-breakpoint
CREATE TABLE "user_roles" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"role_id" integer NOT NULL,
	"environment_id" integer,
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "user_roles_user_id_role_id_environment_id_unique" UNIQUE("user_id","role_id","environment_id")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY NOT NULL,
	"username" text NOT NULL,
	"email" text,
	"password_hash" text NOT NULL,
	"display_name" text,
	"avatar" text,
	"auth_provider" text DEFAULT 'local',
	"mfa_enabled" boolean DEFAULT false,
	"mfa_secret" text,
	"is_active" boolean DEFAULT true,
	"last_login" timestamp,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "users_username_unique" UNIQUE("username")
);
--> statement-breakpoint
CREATE TABLE "vulnerability_scans" (
	"id" serial PRIMARY KEY NOT NULL,
	"environment_id" integer,
	"image_id" text NOT NULL,
	"image_name" text NOT NULL,
	"scanner" text NOT NULL,
	"scanned_at" timestamp NOT NULL,
	"scan_duration" integer,
	"critical_count" integer DEFAULT 0,
	"high_count" integer DEFAULT 0,
	"medium_count" integer DEFAULT 0,
	"low_count" integer DEFAULT 0,
	"negligible_count" integer DEFAULT 0,
	"unknown_count" integer DEFAULT 0,
	"vulnerabilities" text,
	"error" text,
	"created_at" timestamp DEFAULT now()
);
--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auto_update_settings" ADD CONSTRAINT "auto_update_settings_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "container_events" ADD CONSTRAINT "container_events_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "environment_notifications" ADD CONSTRAINT "environment_notifications_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "environment_notifications" ADD CONSTRAINT "environment_notifications_notification_id_notification_settings_id_fk" FOREIGN KEY ("notification_id") REFERENCES "public"."notification_settings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "git_repositories" ADD CONSTRAINT "git_repositories_credential_id_git_credentials_id_fk" FOREIGN KEY ("credential_id") REFERENCES "public"."git_credentials"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "git_stacks" ADD CONSTRAINT "git_stacks_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "git_stacks" ADD CONSTRAINT "git_stacks_repository_id_git_repositories_id_fk" FOREIGN KEY ("repository_id") REFERENCES "public"."git_repositories"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "hawser_tokens" ADD CONSTRAINT "hawser_tokens_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_metrics" ADD CONSTRAINT "host_metrics_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "schedule_executions" ADD CONSTRAINT "schedule_executions_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_events" ADD CONSTRAINT "stack_events_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_sources" ADD CONSTRAINT "stack_sources_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_sources" ADD CONSTRAINT "stack_sources_git_repository_id_git_repositories_id_fk" FOREIGN KEY ("git_repository_id") REFERENCES "public"."git_repositories"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "stack_sources" ADD CONSTRAINT "stack_sources_git_stack_id_git_stacks_id_fk" FOREIGN KEY ("git_stack_id") REFERENCES "public"."git_stacks"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_preferences" ADD CONSTRAINT "user_preferences_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_preferences" ADD CONSTRAINT "user_preferences_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vulnerability_scans" ADD CONSTRAINT "vulnerability_scans_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_logs_user_id_idx" ON "audit_logs" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "audit_logs_created_at_idx" ON "audit_logs" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "container_events_env_timestamp_idx" ON "container_events" USING btree ("environment_id","timestamp");--> statement-breakpoint
CREATE INDEX "host_metrics_env_timestamp_idx" ON "host_metrics" USING btree ("environment_id","timestamp");--> statement-breakpoint
CREATE INDEX "schedule_executions_type_id_idx" ON "schedule_executions" USING btree ("schedule_type","schedule_id");--> statement-breakpoint
CREATE INDEX "sessions_user_id_idx" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "sessions_expires_at_idx" ON "sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "vulnerability_scans_env_image_idx" ON "vulnerability_scans" USING btree ("environment_id","image_id");