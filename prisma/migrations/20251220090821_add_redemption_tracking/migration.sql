/*
  Warnings:

  - You are about to drop the column `barcode_data` on the `cards` table. All the data in the column will be lost.
  - You are about to drop the column `notes` on the `cards` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "palm_devices_api_token_idx";

-- AlterTable
ALTER TABLE "cards" DROP COLUMN "barcode_data",
DROP COLUMN "notes",
ADD COLUMN     "active" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "expiry_date" TIMESTAMP(3),
ALTER COLUMN "color" SET DEFAULT '#0066CC';

-- CreateTable
CREATE TABLE "redemptions" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "user_name" TEXT,
    "card_id" TEXT,
    "campaign_name" TEXT NOT NULL,
    "campaign_vendor" TEXT NOT NULL,
    "palm_device_id" TEXT,
    "location" TEXT,
    "status" TEXT NOT NULL DEFAULT 'verified',
    "redeemed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "redemptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_authentication_logs" (
    "id" TEXT NOT NULL,
    "palm_device_id" TEXT NOT NULL,
    "device_type" TEXT NOT NULL,
    "location" TEXT,
    "success" BOOLEAN NOT NULL DEFAULT false,
    "reason" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "device_authentication_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "redemptions_user_id_idx" ON "redemptions"("user_id");

-- CreateIndex
CREATE INDEX "redemptions_card_id_idx" ON "redemptions"("card_id");

-- CreateIndex
CREATE INDEX "redemptions_palm_device_id_idx" ON "redemptions"("palm_device_id");

-- CreateIndex
CREATE INDEX "redemptions_redeemed_at_idx" ON "redemptions"("redeemed_at");

-- CreateIndex
CREATE INDEX "device_authentication_logs_palm_device_id_idx" ON "device_authentication_logs"("palm_device_id");

-- CreateIndex
CREATE INDEX "device_authentication_logs_timestamp_idx" ON "device_authentication_logs"("timestamp");

-- AddForeignKey
ALTER TABLE "redemptions" ADD CONSTRAINT "redemptions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "redemptions" ADD CONSTRAINT "redemptions_card_id_fkey" FOREIGN KEY ("card_id") REFERENCES "cards"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "redemptions" ADD CONSTRAINT "redemptions_palm_device_id_fkey" FOREIGN KEY ("palm_device_id") REFERENCES "palm_devices"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_authentication_logs" ADD CONSTRAINT "device_authentication_logs_palm_device_id_fkey" FOREIGN KEY ("palm_device_id") REFERENCES "palm_devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;
