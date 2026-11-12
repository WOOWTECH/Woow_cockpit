// SPDX-License-Identifier: LGPL-2.1-or-later
// WOOWTECH integration for cockpit-podman 124. Uses the same Cockpit transport
// as the upstream application, and its existing Podman clients and controls.
export function installManagedOwners(Application, cockpit, superuser) {
    const original = Object.fromEntries(['componentDidMount', 'componentWillUnmount', 'onNavigate', 'init', 'cleanupAfterService']
        .map(name => [name, Application.prototype[name]]));

    Application.prototype.loadManagedOwners = async function () {
        const epoch = this.woowEpoch = (this.woowEpoch || 0) + 1;
        this.woowDiscovering = true;
        try {
            const [raw, session] = await Promise.all([
                cockpit.spawn(['/usr/local/libexec/woowtech-cockpit-services', 'scopes'], {superuser: 'require', err: 'message'}),
                cockpit.user(),
            ]);
            const data = JSON.parse(raw);
            if (!Array.isArray(data.scopes)) throw new Error('Invalid service scopes');
            const managed = data.scopes.filter(s => Number.isSafeInteger(s.uid) && s.uid > 0 && s.uid !== session.id &&
                typeof s.owner === 'string' && /^[a-z_][a-z0-9_-]{0,31}\$?$/.test(s.owner));
            if (epoch !== this.woowEpoch || this.woowUnmounted) return;
            this.woowManaged = managed;
            await new Promise(resolve => this.setState(prev => ({
                users: [...prev.users, ...managed.filter(s => !prev.users.some(u => u.uid === s.uid))
                    .map(s => ({uid: s.uid, name: s.owner, con: null}))],
            }), resolve));
        } catch (error) {
            // Native Cockpit still works without this optional management helper.
            if (epoch === this.woowEpoch) this.woowManaged = [];
            if (!['access-denied', 'not-found', 'disconnected'].includes(error.problem))
                console.warn('Could not load configured Podman owners:', error.message);
        } finally {
            if (epoch === this.woowEpoch && !this.woowUnmounted) {
                this.woowDiscovering = false;
                this.onNavigate();
            }
        }
    };

    Application.prototype.componentDidMount = function () {
        this.woowManaged = [];
        this.woowConnecting = new Map();
        this.woowDiscovering = true;
        this.woowPrivilegeChanged = () => this.loadManagedOwners();
        superuser.addEventListener('changed', this.woowPrivilegeChanged);
        original.componentDidMount.call(this);
        this.loadManagedOwners();
    };

    Application.prototype.componentWillUnmount = function () {
        this.woowUnmounted = true;
        superuser.removeEventListener('changed', this.woowPrivilegeChanged);
        original.componentWillUnmount.call(this);
    };

    Application.prototype.onNavigate = function () {
        const {options, path} = cockpit.location;
        if (path.length) return original.onNavigate.call(this);
        const all = options.owner === undefined || options.owner === 'all';
        // Preserve the requested UID until configured owners have been read.
        if (!all && this.woowDiscovering && !this.state.users.some(u => String(u.uid) === options.owner)) return;
        if (all && this.woowManaged?.length) {
            this.setState({location: options, ownerFilter: 'all', textFilter: options.name || '',
                containersFilter: options.container || 'all'}, () => {
                for (const owner of this.woowManaged) {
                    if (!this.state.users.some(u => u.uid === owner.uid && u.con)) this.init(owner.uid, owner.owner);
                }
            });
            return;
        }
        original.onNavigate.call(this);
    };

    Application.prototype.init = function (uid, name) {
        if (this.woowConnecting?.has(uid)) return this.woowConnecting.get(uid);
        if (this.state.users.some(u => u.uid === uid && u.con)) return Promise.resolve();
        const pending = original.init.call(this, uid, name);
        this.woowConnecting?.set(uid, pending);
        // Keep the guard until React has committed the connection state.
        pending.finally(() => {
            if (!this.woowUnmounted) this.setState({}, () => this.woowConnecting?.delete(uid));
        });
        return pending;
    };

    Application.prototype.cleanupAfterService = function (connection) {
        // An intentionally closed, old connection must not remove a newer one
        // after switching Owner away and back quickly.
        if (!this.state.users.some(u => u.uid === connection.uid && u.con === connection)) return;
        original.cleanupAfterService.call(this, connection);
    };
}
