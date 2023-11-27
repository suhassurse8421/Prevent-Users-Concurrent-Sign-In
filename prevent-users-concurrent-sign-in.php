<?php
/**
 * @version 1.0
 */
/*
Plugin Name: Prevent Users Concurrent Sign In
Description: The "Prevent Users Concurrent Sign In" plugin for WordPress is a powerful tool designed to enhance the security of your website by preventing users from sharing sign-in information and blocking simultaneous logins.
Author: Plainsurf Solutions
Author URI: https://plainsurf.com/
Requires PHP at least: 7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Version: 1.0
*/

/**
 * Add a new field to the admin profile page, to set session sign-in restriction to the user callback
 */
 
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

function pucsi_logins_count_field_callback( $user ) {
    //If the data already exists in the new meta data field, it obtains new data in the region,
    $value = get_user_meta($user->ID, '_login_count');
    //Set up a label filter to allow users to customize labels when they need to use filters
    $fieldLable = apply_filters( 'pucsi_restrict_number_of_sign_ins_label', esc_html__( 'Restrict the number of sign-in sessions at a time', 'pucsi' ) );
    //Create a simple HTML entry field to save the number of sign-in sessions
    $html = '<table class="form-table">
                <tbody>
                    <tr class="form-field">
                        <th scope="row"><label for="_login_count">' . esc_html( $fieldLable ) . '</label></th>
                        <td><input name="_login_count" id="_login_count" value="'.esc_attr( stripslashes( $value[0] ) ).'" type="text" size="10"></td>
                    </tr>
                <tbody>
	            </table>';
    //Display a snippet of HTML input
    echo wp_kses_post( $html );
}

/**
 * Add a new field to the admin profile page, to set session sign-in restriction to the user hooks
 */
add_action( 'show_user_profile', 'pucsi_logins_count_field_callback' );
add_action( 'edit_user_profile', 'pucsi_logins_count_field_callback' );

/**
 * When the administrator updates the user profile, update the new field information on the administration profile page
 * (that is,  set session sign-in restriction to the user) callback.
 */
function pucsi_update_logins_count_field_callback( $user_id ) {

    //Check whether the user has permission to edit
    if ( !current_user_can( 'edit_user', $user_id ) && is_admin() ){
        //return
        return false;
    }
    //Check whether the custom field (that is, '_login_count' ) has set, if set update data to user meta
    if (isset( $_POST['_login_count'] ) ) {
        //Save custom field data to the user's meta
        update_user_meta( $user_id, '_login_count', sanitize_text_field( $_POST['_login_count'] ) );
    }

}

/**
 * When the administrator updates the user profile, update the new field information on the administration profile page
 * (that is,  set session sign-in restriction to the user) hooks.
 */
add_action( 'personal_options_update', 'pucsi_update_logins_count_field_callback' );
add_action( 'edit_user_profile_update', 'pucsi_update_logins_count_field_callback' );

/**
 * Displaying additional newly created field header at administrator manages all user page callback
 */
function pucsi_modify_user_table_callback( $column ) {
    //Set up a header label filter to allow users to customize labels when they need to use filters
    $headerLable = apply_filters('pucsi_restrict_number_of_sign_ins_header', esc_html__( 'Restrict the number of sign-in sessions at a time', 'pucsi' ) );
    //set the column header
    $column['_login_count'] = $headerLable;
    //return
    return $column;
}

/**
 * Displaying additional newly created field header at administrator manages all user page hook
 */
add_filter( 'manage_users_columns', 'pucsi_modify_user_table_callback' );

/**
 * Displaying additional newly created field user data at administrator manages all user page callback
 */
function pucsi_modify_user_table_row_callback( $value, $column_name, $user_id ) {
    //Check whether the newly created field exists and then obtains the newly created field data from user meta
    switch ($column_name) {
        case '_login_count' :
            //Obtains the newly created field data from user meta
            return get_the_author_meta( '_login_count', $user_id );
            break;
        default:
    }
    //return restrict the number of sign-in sessions at a time value
    return $value;
}

/**
 * Displaying additional newly created field user data at administrator manages all user page hook
 */
add_filter( 'manage_users_custom_column', 'pucsi_modify_user_table_row_callback', 10, 3 );


/**
 * First of all, the meta user receives all user data for which no newly created field data has been set
 * and sets the default value for that user to one callback
 */
function pucsi_set_logins_count_default_field_callback(){
    //Prepare query arguments and get all data which users are not set newly created field data at user meta,
    $args = array(  'fields' => array( 'ID' ),
        'meta_query' => array(
            array(
                'key' => '_login_count',
                'compare' => 'NOT EXISTS'
            ))
    );
    //get all users data which users are not set newly created field data at user meta
    $users = get_users($args);
    //check whether such user's exists
    if(!empty($users)){
        //loop thorough all users data which users are not set
        foreach ($users as $user){
            //set each user '_login_count' newly created custom field default value as one
            update_user_meta($user->ID, '_login_count',1);
        }
    }
}

/**
 * First of all, the meta user receives all user data for which no newly created field data has been set
 * and sets the default value for that user to one hook
 */
add_action('init','pucsi_set_logins_count_default_field_callback');

/**
 * First, it is necessary to obtain all the user data set by session_tokens,
 * make sure that each user session limit is more restricted than the limit specified by the administrator,
 * then destroy all login sessions, so user can avoid past logs of conflicts callback
 */
function pucsi_cleaned_up_user_sessions_callback(){
    //Prepare query arguments and get all users data which users are set session_tokens at user meta
    $args = array(  'fields' => array( 'ID' ),
        'meta_query' => array(
            array(
                'key' => 'session_tokens',
                'compare' => 'EXISTS'
            ))
    );
    //get all users data which users are set session_tokens at user meta
    $users = get_users($args);
    //check whether such user's exists
    if(!empty($users)){
        //loop thorough all users data which users are set
        foreach ($users as $user){
            //get user id
            $user_id = $user->ID;
            //login count
            $_login_count = get_the_author_meta('_login_count', $user_id);
            //get user sessions
            $user_sessions = get_user_meta($user_id, 'session_tokens', true);
            // get login timestamp from all sessions
            $login_timestamps = array_values(wp_list_pluck($user_sessions, 'login'));
            //check whether user's session less then the limit specified by the administrator, then continue
            if (count($login_timestamps) <= $_login_count) {
                continue;
            }
            //Allow users to customize or extend functionality by providing following action hooks
            do_action('pucsi_before_destroying_restricted_user_session',$user,$user_id);
            //get all active sessions of the user
            $sessions = WP_Session_Tokens::get_instance($user_id);
            // we got all the sessions, just destroy them all at once.
            $sessions->destroy_all();
            //Allow users to customize or extend functionality by providing following action hooks
            do_action('pucsi_after_destroying_restricted_user_session',$user,$user_id);
        }
    }
}

/**
 * First, it is necessary to obtain all the user data set by session_tokens,
 * make sure that each user session limit is more restricted than the limit specified by the administrator,
 * then destroy all login sessions, so user can avoid past logs of conflicts hook
 */
add_action('init','pucsi_cleaned_up_user_sessions_callback');

/**
 * Initially, when user trying to login,
 * check whether the user session limit is more restricted than the limit specified by the administrator,
 * when using "authenticate" filter hook,
 * if it is more not allow him to login and show the error message at the login screen callback
 */
function pucsi_auth_signon_callback( $user, $username, $password ) {
    //Check whether user name exists, then go forward otherwise return user as it is
    if (!empty($username)) {
        //get current user id
        $user_id = $user->ID;
        //get the user login allowed session count
        $_login_count = get_the_author_meta('_login_count', $user_id);
        //get user sessions
        $user_sessions = get_user_meta($user_id, 'session_tokens', true);
        // get login timestamp from all sessions
        $login_timestamps = (!empty($user_sessions)) ? array_values(wp_list_pluck($user_sessions, 'login')):array();
        //check whether user's session less then the limit specified by the administrator, then continue
        if (count($login_timestamps) <= $_login_count) {
            //return
            return $user;
        } else {
            //Allow users to customize or extend functionality by providing following action hooks
            do_action('pucsi_before_error_restricted_user_session',$user,$_login_count,$login_timestamps);
	   //get all active sessions of the user
            $sessions = WP_Session_Tokens::get_instance($user_id);
            // we got all the sessions, just destroy them all at once.
            $sessions->destroy_all();		
            //message
            $message = sprintf( esc_html__( 'Max %s login sessions are allowed at a time. Please contact your site administrator for more details.', 'pucsi' ), $_login_count );
            //Set up a error message filter to allow users to customize error message when they need to use filters
            $message = apply_filters('pucsi_restrict_number_of_sign_ins_error_message',$message,count($login_timestamps),$_login_count);
            //return a error message
            return new WP_Error('_login_count_error', $message);
        }
    }
    //return
    return $user;
}

/**
 * Initially, when user trying to login,
 * check whether the user session limit is more restricted than the limit specified by the administrator,
 * when using "authenticate" filter hook,
 * if it is more not allow him to login and show the error message at the login screen hook
 */
add_filter( 'authenticate', 'pucsi_auth_signon_callback', 30, 3 );
