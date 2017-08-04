/**
 * @copyright Copyright (c) 2017 Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

$(document).ready(function(){
    $('#password-policy').on('click','#save-pass-length',
        function() {
            OC.msg.startSaving('#of-msg');
            var length = $('#security-min-password-length').val();
            if($.isNumeric(length) && length>0) {
                OC.AppConfig.setValue('security', 'min_password_length', length);
                OC.msg.finishedSuccess('#security-min-password-length-message', OC.L10N.translate('Security', 'Length Saved'));
            } else {
                OC.msg.finishedError('#security-min-password-length-message', OC.L10N.translate('Security', 'Length must be positive integer'));
            }
        }
    );

    $('#security-brute-force-protection-enabled').click(function() {
        var value;
        (this.checked) ? value = '1': value = '0';
        OC.AppConfig.setValue('security', 'enable_brute_force_protection', value);
    });
    $('#security-enforce-upper-lower-case').click(function() {
        var value;
        (this.checked) ? value = '1': value = '0';
        OC.AppConfig.setValue('security', 'enforce_upper_lower_case', value);
    });
    $('#security-enforce-numerical-characters').click(function() {
        var value;
        (this.checked) ? value = '1': value = '0';
        OC.AppConfig.setValue('security', 'enforce_numeric_characters', value);
    });
    $('#security-enforce-special-characters').click(function() {
        var value;
        (this.checked) ? value = '1': value = '0';
        OC.AppConfig.setValue('security', 'enforce_special_characters', value);
    });
});