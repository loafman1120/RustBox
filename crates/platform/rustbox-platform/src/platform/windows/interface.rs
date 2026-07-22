pub(super) fn default_route_interface_name() -> Option<String> {
    let interface = netdev::get_default_interface().ok()?;
    // socket2-ext resolves adapters through ipconfig::Adapter::friendly_name.
    // netdev's `name` is the internal adapter name on Windows and is not
    // accepted by that API.
    interface.friendly_name
}

pub(super) fn default_route_interface_index() -> Option<u32> {
    netdev::get_default_interface()
        .ok()
        .map(|interface| interface.index)
}
