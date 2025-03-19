/**
 * Profile Dropdown Menu Functionality
 * Handles user profile dropdown menu interactions
 */

// Initialize profile dropdown when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initProfileDropdown();
    
    // Load user data from server
    loadUserData();
});

/**
 * Initialize the profile dropdown functionality
 */
function initProfileDropdown() {
    const profileButton = document.getElementById('profile-dropdown-button');
    const dropdownMenu = document.getElementById('profile-dropdown-menu');
    
    // Toggle dropdown when profile button is clicked
    if (profileButton) {
        profileButton.addEventListener('click', function(e) {
            e.stopPropagation();
            dropdownMenu.classList.toggle('show');
        });
    }
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (dropdownMenu && dropdownMenu.classList.contains('show') && 
            !dropdownMenu.contains(e.target) && 
            e.target !== profileButton) {
            dropdownMenu.classList.remove('show');
        }
    });
}

/**
 * Load user data from server
 */
function loadUserData() {
    fetch('/api/get_profile_data')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update user info in dropdown
                updateUserInfo(data.data);
            }
        })
        .catch(error => {
            console.error('Error fetching user data:', error);
        });
}

/**
 * Update user information in the dropdown
 * @param {Object} userData - User data from server
 */
function updateUserInfo(userData) {
    // Update username and email in dropdown
    const usernameElement = document.querySelector('.dropdown-user-info h3');
    const emailElement = document.querySelector('.dropdown-user-info p');
    
    if (usernameElement && userData.username) {
        usernameElement.textContent = userData.username;
    }
    
    if (emailElement) {
        emailElement.textContent = userData.email || '';
    }
}

/**
 * Handle logout functionality
 */
function handleLogout() {
    // Redirect to the logout route
    window.location.href = '/logout';
} 