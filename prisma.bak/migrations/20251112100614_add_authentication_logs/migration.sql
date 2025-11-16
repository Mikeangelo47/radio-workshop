-- CreateTable
CREATE TABLE "authentication_logs" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "device_type" TEXT NOT NULL,
    "location" TEXT,
    "success" BOOLEAN NOT NULL DEFAULT true,
    "authenticated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "authentication_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "authentication_logs_user_id_idx" ON "authentication_logs"("user_id");

-- CreateIndex
CREATE INDEX "authentication_logs_authenticated_at_idx" ON "authentication_logs"("authenticated_at");

-- AddForeignKey
ALTER TABLE "authentication_logs" ADD CONSTRAINT "authentication_logs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
