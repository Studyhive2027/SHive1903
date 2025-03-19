/**
 * Avatar Manager
 * Handles avatar uploads and management with server integration
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize avatar display from server
    initializeAvatar();
    
    // Set up avatar change handlers
    setupAvatarChangeHandlers();
});

/**
 * Initialize avatar display from server data
 */
function initializeAvatar() {
    fetch('/api/get_profile_pic')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.profile_pic) {
                const profilePicUrl = '/static/avatars/' + data.profile_pic;
                updateAvatarDisplay(profilePicUrl);
            }
        })
        .catch(error => {
            console.error('Error fetching profile picture:', error);
        });
}

/**
 * Update avatar display with the given image URL
 * @param {string} imageUrl - URL of the image to display
 */
function updateAvatarDisplay(imageUrl) {
    // Update all avatar elements on the page
    const avatarElements = [
        { img: 'profile-avatar-img', icon: 'profile-avatar-icon' },  // Home page avatar
        { img: 'dropdown-avatar-img', icon: 'dropdown-avatar-icon' }, // Dropdown menu avatar
        { img: 'profile-page-avatar', icon: 'profile-page-icon' },
        { img: 'profile-settings-avatar', icon: 'profile-settings-icon' },
        { img: 'current-avatar-img', icon: 'current-avatar-icon' },
        { img: 'preview-profile', icon: 'preview-profile-icon' },
        { img: 'preview-comment', icon: 'preview-comment-icon' },
        { img: 'preview-dropdown', icon: 'preview-dropdown-icon' }
    ];

    avatarElements.forEach(element => {
        const imgElement = document.getElementById(element.img);
        const iconElement = document.getElementById(element.icon);
        
        if (imgElement) {
            imgElement.src = imageUrl;
            imgElement.style.display = 'block';
            if (iconElement) {
                iconElement.style.display = 'none';
            }
        }
    });
}

/**
 * Set up avatar change handlers
 */
function setupAvatarChangeHandlers() {
    // Handle file input changes
    const fileInputs = [
        'avatar-input-profile',
        'profile-pic-input',
        'avatar-upload'
    ];

    fileInputs.forEach(inputId => {
        const input = document.getElementById(inputId);
        if (input) {
            input.addEventListener('change', handleAvatarFileChange);
        }
    });
}

/**
 * Handle avatar file change events
 * @param {Event} e - The change event
 */
function handleAvatarFileChange(e) {
    const file = e.target.files[0];
    if (!file) return;

    // Validate file type
    if (!file.type.match('image.*')) {
        showNotification('error', 'Please select an image file');
        return;
    }

    // Validate file size (max 2MB)
    if (file.size > 2 * 1024 * 1024) {
        showNotification('error', 'Image size should be less than 2MB');
        return;
    }

    const formData = new FormData();
    formData.append('profile_pic', file);

    fetch('/upload_profile_pic', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const profilePicUrl = '/static/avatars/' + data.profile_pic;
            updateAvatarDisplay(profilePicUrl);
            showNotification('success', 'Profile picture updated successfully');
        } else {
            showNotification('error', data.message || 'Failed to update profile picture');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('error', 'An error occurred while updating profile picture');
    });
}

/**
 * Show notification message
 * @param {string} type - Type of notification ('success' or 'error')
 * @param {string} message - Message to display
 */
function showNotification(type, message) {
    const notification = document.getElementById('notification');
    if (notification) {
        notification.textContent = message;
        notification.className = 'notification ' + type;
        notification.style.display = 'block';
        
        setTimeout(() => {
            notification.style.display = 'none';
        }, 3000);
    }
} 