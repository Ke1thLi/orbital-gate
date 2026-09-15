window.AdminLegacy = {
    generateAdminToken(username) {
        return btoa(`${username}:admin:legacy`);
    }
};