//! Resource monitoring and management

use log::{debug, info};
use sysinfo::System;

/// Resource usage limits
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for configuration
pub struct ResourceLimits {
    /// Maximum CPU usage percentage (0-100)
    pub cpu_percent: f64,
    /// Maximum memory usage percentage (0-100)
    pub memory_percent: f64,
    /// Minimum free memory in bytes
    pub min_free_memory: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_percent: 70.0,
            memory_percent: 70.0,
            min_free_memory: 2 * 1024 * 1024 * 1024, // 2 GB
        }
    }
}

/// Resource manager for monitoring system resources
pub struct ResourceManager {
    system: System,
    #[allow(dead_code)]
    limits: ResourceLimits,
    safe_mode: bool,
}

impl ResourceManager {
    /// Create a new resource manager
    #[must_use]
    pub fn new(limits: ResourceLimits, safe_mode: bool) -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            system,
            limits,
            safe_mode,
        }
    }

    /// Calculate optimal worker count based on system resources
    #[allow(clippy::cast_possible_truncation)]
    pub fn calculate_worker_count(&mut self, file_count: usize, max_workers: usize) -> usize {
        self.system.refresh_all();

        let cpu_count = self.system.cpus().len();
        let total_memory = self.system.total_memory();
        let available_memory = self.system.available_memory();

        debug!(
            "System resources: {} CPUs, {} MB total memory, {} MB available",
            cpu_count,
            total_memory / 1024 / 1024,
            available_memory / 1024 / 1024
        );

        // Start with CPU count
        let mut workers = cpu_count;

        // Apply user-specified max workers
        if max_workers > 0 {
            workers = workers.min(max_workers);
        }

        // Adjust for safe mode (use 50% of resources)
        if self.safe_mode {
            workers = (workers / 2).max(1);
            debug!("Safe mode: reduced workers to {workers}");
        }

        // Adjust for memory constraints
        // Estimate ~200MB per worker for PST processing
        let memory_per_worker = 200 * 1024 * 1024u64;
        let memory_workers = (available_memory / memory_per_worker) as usize;
        workers = workers.min(memory_workers.max(1));

        // Never exceed file count
        workers = workers.min(file_count);

        // Reasonable bounds
        workers = workers.clamp(1, 24);

        info!("Calculated {workers} workers for {file_count} files");

        workers
    }

    /// Check if processing should be throttled based on resource usage
    #[allow(dead_code)]
    pub fn should_throttle(&mut self) -> bool {
        self.system.refresh_cpu_all();
        self.system.refresh_memory();

        let cpu_usage = self.get_cpu_usage();
        let memory_usage = self.get_memory_usage();
        let available_memory = self.system.available_memory();

        let throttle = cpu_usage > self.limits.cpu_percent
            || memory_usage > self.limits.memory_percent
            || available_memory < self.limits.min_free_memory;

        if throttle {
            debug!(
                "Throttling: CPU {:.1}% (limit {:.1}%), Memory {:.1}% (limit {:.1}%), Available {} MB (min {} MB)",
                cpu_usage,
                self.limits.cpu_percent,
                memory_usage,
                self.limits.memory_percent,
                available_memory / 1024 / 1024,
                self.limits.min_free_memory / 1024 / 1024
            );
        }

        throttle
    }

    /// Get current CPU usage percentage
    #[allow(dead_code, clippy::cast_precision_loss)]
    #[must_use]
    pub fn get_cpu_usage(&self) -> f64 {
        let cpus = self.system.cpus();
        if cpus.is_empty() {
            return 0.0;
        }
        cpus.iter()
            .map(|cpu| f64::from(cpu.cpu_usage()))
            .sum::<f64>()
            / cpus.len() as f64
    }

    /// Get current memory usage percentage
    #[allow(dead_code, clippy::cast_precision_loss)]
    #[must_use]
    pub fn get_memory_usage(&self) -> f64 {
        let total = self.system.total_memory() as f64;
        let used = self.system.used_memory() as f64;
        if total == 0.0 {
            return 0.0;
        }
        (used / total) * 100.0
    }

    /// Get available memory in bytes
    #[allow(dead_code)]
    #[must_use]
    pub fn available_memory(&self) -> u64 {
        self.system.available_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_manager_creation() {
        let limits = ResourceLimits::default();
        let manager = ResourceManager::new(limits, false);
        assert!(!manager.system.cpus().is_empty());
    }

    #[test]
    fn test_worker_count_calculation() {
        let limits = ResourceLimits::default();
        let mut manager = ResourceManager::new(limits, false);

        // Should return at least 1 worker
        let workers = manager.calculate_worker_count(10, 0);
        assert!(workers >= 1);
        assert!(workers <= 10);

        // Should respect max_workers
        let workers = manager.calculate_worker_count(100, 4);
        assert!(workers <= 4);
    }

    #[test]
    fn test_safe_mode_workers() {
        let limits = ResourceLimits::default();
        let mut manager_normal = ResourceManager::new(limits.clone(), false);
        let mut manager_safe = ResourceManager::new(limits, true);

        let normal_workers = manager_normal.calculate_worker_count(100, 0);
        let safe_workers = manager_safe.calculate_worker_count(100, 0);

        // Safe mode should use fewer workers
        assert!(safe_workers <= normal_workers);
    }

    #[test]
    fn test_resource_metrics() {
        let limits = ResourceLimits::default();
        let manager = ResourceManager::new(limits, false);

        // Should return valid percentages
        let cpu = manager.get_cpu_usage();
        let memory = manager.get_memory_usage();

        assert!((0.0..=100.0).contains(&cpu));
        assert!((0.0..=100.0).contains(&memory));
    }
}
