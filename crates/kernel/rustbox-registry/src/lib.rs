//! Construction-time module registries.

use std::collections::HashMap;

pub trait Factory: Send + Sync {
    fn kind(&self) -> &'static str;
}

#[derive(Debug, Eq, PartialEq)]
pub enum RegistryError {
    DuplicateKind(String),
    UnknownKind(String),
}

pub struct Registry<T: Factory + ?Sized> {
    factories: HashMap<&'static str, Box<T>>,
}

impl<T: Factory + ?Sized> Registry<T> {
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    pub fn register(&mut self, factory: Box<T>) -> Result<(), RegistryError> {
        let kind = factory.kind();
        if self.factories.contains_key(kind) {
            return Err(RegistryError::DuplicateKind(kind.to_string()));
        }

        self.factories.insert(kind, factory);
        Ok(())
    }

    pub fn get(&self, kind: &str) -> Result<&T, RegistryError> {
        self.factories
            .get(kind)
            .map(Box::as_ref)
            .ok_or_else(|| RegistryError::UnknownKind(kind.to_string()))
    }

    pub fn len(&self) -> usize {
        self.factories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

impl<T: Factory + ?Sized> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ModuleCategory {
    Inbound,
    Outbound,
    Transport,
    DnsTransport,
    Inspector,
    Stack,
}

pub trait ModuleFactory: Factory {
    fn category(&self) -> ModuleCategory;

    fn required_capabilities(&self) -> &[CapabilityRequirement];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CapabilityRequirement {
    Network,
    Clock,
    Entropy,
    TaskSpawner,
    PacketDevice,
    NetworkControl,
    Storage,
    Observability,
}

#[derive(Default)]
pub struct ModuleRegistry {
    inbound: Registry<dyn ModuleFactory>,
    outbound: Registry<dyn ModuleFactory>,
    transport: Registry<dyn ModuleFactory>,
    dns_transport: Registry<dyn ModuleFactory>,
    inspector: Registry<dyn ModuleFactory>,
    stack: Registry<dyn ModuleFactory>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, factory: Box<dyn ModuleFactory>) -> Result<(), RegistryError> {
        match factory.category() {
            ModuleCategory::Inbound => self.inbound.register(factory),
            ModuleCategory::Outbound => self.outbound.register(factory),
            ModuleCategory::Transport => self.transport.register(factory),
            ModuleCategory::DnsTransport => self.dns_transport.register(factory),
            ModuleCategory::Inspector => self.inspector.register(factory),
            ModuleCategory::Stack => self.stack.register(factory),
        }
    }

    pub fn get(
        &self,
        category: ModuleCategory,
        kind: &str,
    ) -> Result<&dyn ModuleFactory, RegistryError> {
        match category {
            ModuleCategory::Inbound => self.inbound.get(kind),
            ModuleCategory::Outbound => self.outbound.get(kind),
            ModuleCategory::Transport => self.transport.get(kind),
            ModuleCategory::DnsTransport => self.dns_transport.get(kind),
            ModuleCategory::Inspector => self.inspector.get(kind),
            ModuleCategory::Stack => self.stack.get(kind),
        }
    }
}
