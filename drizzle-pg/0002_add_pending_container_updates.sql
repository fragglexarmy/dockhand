CREATE TABLE "pending_container_updates" (
	"id" serial PRIMARY KEY NOT NULL,
	"environment_id" integer NOT NULL,
	"container_id" text NOT NULL,
	"container_name" text NOT NULL,
	"current_image" text NOT NULL,
	"checked_at" timestamp DEFAULT now(),
	"created_at" timestamp DEFAULT now(),
	CONSTRAINT "pending_container_updates_environment_id_container_id_unique" UNIQUE("environment_id","container_id")
);
--> statement-breakpoint
ALTER TABLE "pending_container_updates" ADD CONSTRAINT "pending_container_updates_environment_id_environments_id_fk" FOREIGN KEY ("environment_id") REFERENCES "public"."environments"("id") ON DELETE cascade ON UPDATE no action;