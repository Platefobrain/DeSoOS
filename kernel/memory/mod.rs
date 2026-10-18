mod demand;
mod frame;
pub mod heap;
pub mod layout;
mod paging;

#[allow(unused_imports)]
pub use layout::{
    phys_to_virt,
    direct_to_phys,
    kernel_layout,
    is_stack_guard,
    DIRECT_MAP_BASE,
    KERNEL_BASE,
};

#[allow(unused_imports)]
pub use frame::{
    init,
    alloc_frame,
    alloc_frame_user,
    free_frames_approx,
    user_reserve_stats,
    alloc_frames,
    alloc_frames_below,
    free_frame,
    free_frames,
    bitmap_info,
    free_frame_count,
    highest_physical_address,
    overlaps_conventional,
    overlaps_known_memory,
    trampoline_frame,
    alloc_frame_below,
    enable_frame_caches,
};

#[allow(unused_imports)]
pub use paging::{
    init as paging_init,
    map_page,
    unmap_page,
    unmap_range_free,
    translate,
    map_write_combining,
    map_mmio,
    map_firmware,
    split_direct_map_huge,
    kernel_cr3,
    nx_flag,
    kernel_data_flags,
    USER,
    NO_EXECUTE,
    page_flags,
    pat_supported,
    read_pat,
    init_ap_cpu as paging_init_ap_cpu,
    PAT_WC,
    PRESENT,
    WRITABLE,
    WRITE_THROUGH,
    CACHE_DISABLE,
};

#[allow(unused_imports)]
pub use heap::{
    init as heap_init,
    used_bytes as heap_used_bytes,
    mapped_bytes as heap_mapped_bytes,
};

#[allow(unused_imports)]
pub use demand::{
    handle_page_fault,
    faults_handled as demand_faults,
    DEMAND_START,
    DEMAND_SIZE,
};

#[cfg(selftest)]
pub use paging::retarget_page_local;

// Self-tests – only in the `./build.sh --selftest` build.
#[cfg(selftest)]
pub use frame::self_test;
#[cfg(selftest)]
pub use paging::self_test as paging_self_test;
#[cfg(selftest)]
pub use heap::self_test as heap_self_test;
#[cfg(selftest)]
pub use demand::self_test as demand_self_test;
