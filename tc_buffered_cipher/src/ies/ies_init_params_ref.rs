/// What [`BufferedIesCipher`](crate::BufferedIesCipher) is initialized with: this party's
/// private key, the other party's public key and the IES parameters, the three arguments of
/// Bouncy Castle's `IesEngine.Init`, borrowed. Nothing is checked here; the engine checks them in
/// `init`. There is no `Debug`, which would print the private key. Constant time: it only
/// holds borrowed values.
pub struct IesInitParamsRef<'a, Priv: ?Sized, Pub: ?Sized, P: ?Sized> {
    private_key: &'a Priv,
    public_key: &'a Pub,
    params: &'a P,
}

impl<Priv: ?Sized, Pub: ?Sized, P: ?Sized> Clone for IesInitParamsRef<'_, Priv, Pub, P> {
    /// Copies the three references. Constant time.
    fn clone(&self) -> Self {
        *self
    }
}

impl<Priv: ?Sized, Pub: ?Sized, P: ?Sized> Copy for IesInitParamsRef<'_, Priv, Pub, P> {}

impl<'a, Priv: ?Sized, Pub: ?Sized, P: ?Sized> IesInitParamsRef<'a, Priv, Pub, P> {
    /// This party's `private_key`, the other party's `public_key` and the IES `params`.
    /// Constant time.
    pub const fn new(private_key: &'a Priv, public_key: &'a Pub, params: &'a P) -> Self {
        Self {
            private_key,
            public_key,
            params,
        }
    }

    /// This party's private key. Constant time.
    pub const fn private_key(&self) -> &'a Priv {
        self.private_key
    }

    /// The other party's public key. Constant time.
    pub const fn public_key(&self) -> &'a Pub {
        self.public_key
    }

    /// The IES parameters. Constant time.
    pub const fn params(&self) -> &'a P {
        self.params
    }
}
