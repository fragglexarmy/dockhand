CREATE TABLE "stack_environment_variables" (
	"id" serial PRIMARY KEY NOT NULL,
	"stack_name" text NOT NULL,
	"environment_id" integer,
	"key" text NOT NULL,
	"value" text NOT NULL,
	"is_secret" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now(),
	CONSTRAINT "stack_environment_variables_stack_name_environment_id_key_unique" UNIQUE("stack_name","environment_id","key")
);
--> statement-breakpoint
ALTER TABLE "git_stacks" ADD COLUMN "env_file_path" text;--> statement-breakpoint
ALTER TABLE "stack_environment_variables" ADD CONSTRAINT "stack_environment_variables_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;