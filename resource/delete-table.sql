-- インデックスを削除
DROP INDEX IF EXISTS idx_packets_node_timestamp_included;
DROP INDEX IF EXISTS idx_packets_recent;

-- 外部キー制約の為
DROP TABLE IF EXISTS packet_details CASCADE;

-- ハイパーテーブルの削除（packetsテーブルも同時に削除される）
DROP TABLE IF EXISTS packets CASCADE;
