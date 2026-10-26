pub const QUOTA_DOWNLOAD: u8 = 1;
pub const QUOTA_UPLOAD: u8 = 2;

/// Absolute byte thresholds, ordered minute/hour/day/week/month/lifetime.
/// u64::MAX means unlimited; zero means exhausted even before any traffic.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaThresholds {
    pub combined: [u64; 6],
    pub download: [u64; 6],
    pub upload: [u64; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for QuotaThresholds {}

impl QuotaThresholds {
    #[inline(always)]
    pub fn blocks(&self, download_bytes: u64, upload_bytes: u64, is_download: bool) -> bool {
        reached(&self.combined, download_bytes.saturating_add(upload_bytes))
            || if is_download {
                reached(&self.download, download_bytes)
            } else {
                reached(&self.upload, upload_bytes)
            }
    }
}

#[inline(always)]
fn reached(limits: &[u64; 6], used: u64) -> bool {
    (limits[0] != u64::MAX && used >= limits[0])
        || (limits[1] != u64::MAX && used >= limits[1])
        || (limits[2] != u64::MAX && used >= limits[2])
        || (limits[3] != u64::MAX && used >= limits[3])
        || (limits[4] != u64::MAX && used >= limits[4])
        || (limits[5] != u64::MAX && used >= limits[5])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_enforcement_is_independent_in_every_period() {
        for period in 0..6 {
            let mut thresholds = QuotaThresholds {
                combined: [u64::MAX; 6],
                download: [u64::MAX; 6],
                upload: [u64::MAX; 6],
            };
            thresholds.upload[period] = 100;
            assert!(!thresholds.blocks(200, 99, false));
            assert!(thresholds.blocks(200, 100, false));
            assert!(!thresholds.blocks(200, 100, true));
            thresholds.download[period] = 201;
            assert!(!thresholds.blocks(200, 100, true));
            assert!(thresholds.blocks(201, 100, true));
            thresholds.combined[period] = 50;
            assert!(thresholds.blocks(25, 25, true));
            assert!(thresholds.blocks(25, 25, false));
        }
    }

    #[test]
    fn unlimited_and_zero_thresholds_work_without_counters() {
        let mut thresholds = QuotaThresholds {
            combined: [u64::MAX; 6],
            download: [u64::MAX; 6],
            upload: [u64::MAX; 6],
        };
        assert!(!thresholds.blocks(u64::MAX, 1, false));
        thresholds.download[0] = 0;
        assert!(thresholds.blocks(0, 0, true));
        assert!(!thresholds.blocks(0, 0, false));
    }
}
