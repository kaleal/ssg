# platform = multi_platform_ubuntu,multi_platform_debian

{{{ bash_pam_pwhistory_enable('cac_pwhistory', 'requisite', apply=false) }}}

{{{ bash_instantiate_variables("var_password_pam_remember") }}}

# Update the value in place so a repeated remediation preserves option order.
sed -i -E '/pam_pwhistory\.so/ {
    s/([[:space:]])remember=[^[:space:]]+/\1remember='"$var_password_pam_remember"'/g
    /[[:space:]]remember=/! s/$/ remember='"$var_password_pam_remember"'/
}' /usr/share/pam-configs/cac_pwhistory || exit 1

# Existing profiles may lack use_authtok; do not add it to Password-Initial.
sed -i -E '/^Password:/,/^[^[:space:]]/ {
    /^[^[:space:]]/ { /^Password:/! b }
    /pam_pwhistory\.so/ {
        /\buse_authtok\b/! s/pam_pwhistory\.so/pam_pwhistory.so use_authtok/
    }
}' /usr/share/pam-configs/cac_pwhistory || exit 1

{{{ bash_apply_pam_auth_update(['cac_pwhistory'], ['pwhistory']) }}}
if ! grep -qP '^\s*password\s+requisite\s+pam_pwhistory\.so\s+.*\bremember='"$var_password_pam_remember"'(\s|$)' /etc/pam.d/common-password ||
   ! grep -qP '^\s*password\s+requisite\s+pam_pwhistory\.so\s+.*\buse_authtok(\s|$)' /etc/pam.d/common-password; then
    echo 'pam-auth-update did not apply the requested password history options' >&2
    exit 1
fi
