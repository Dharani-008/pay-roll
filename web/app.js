fetch('/api/account').then(response => {
    if (response.status === 401) {
        location.href = '/login.html';
        return null;
    }
    if (!response.ok) return null;
    return response.json();
}).then(account => {
    if (!account) return;
    const initials = account.displayName.trim().split(/\s+/).map(part => part[0]).join('').slice(0, 2).toUpperCase();
    document.querySelectorAll('[data-account-name]').forEach(element => {
        element.textContent = account.displayName;
    });
    document.querySelectorAll('[data-account-initials]').forEach(element => {
        element.textContent = initials || 'PA';
        element.setAttribute('aria-label', account.displayName);
    });
});
