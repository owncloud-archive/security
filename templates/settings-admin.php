<?php
/**
 *
 * @author Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
 * @copyright Copyright (c) 2017, ownCloud GmbH.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */
/** @var array $_ */
/** @var \OCP\IL10N $l */
script('security', 'settings-admin');
?>
<div id="security-brute-force-protection" class="section">
    <h2 class="inlineblock"><?php p($l->t('Brute Force Protection')); ?></h2>
    <span id="security-save-bfp-settings-message" class="msg"></span>
    <div>
        <label for="security-bfp-threshold-time"><?php p($l->t('Count failed login attempts over how many seconds?')) ?></label><br>
        <input type="number" id="security-bfp-threshold-time"  value="<?php p($_['bruteForceProtectionTimeThreshold']) ?>"><br>
        <label for="security-bfp-fail-tolerance"><?php p($l->t('Ban after how many failed login attempts?')) ?></label><br>
        <input type="number" id="security-bfp-fail-tolerance"  value="<?php p($_['bruteForceProtectionFailTolerance']) ?>"><br>
        <label for="security-bfp-ban-period"><?php p($l->t('Ban for how many seconds?')) ?></label><br>
        <input type="number" id="security-bfp-ban-period" value="<?php p($_['bruteForceProtectionBanPeriod']) ?>"><br>
        <button id="save-bfp-settings" class="save"><?php p($l->t('Save settings'));?></button>
	</div>
</div>
<div id="security-password-policy" class="section">
    <h2 class="inlineblock"><?php p($l->t('Password Policy')); ?></h2>
    <div>
		<label for="security-min-password-length"><?php p($l->t('Determine minimum password length')) ?></label>
		<input type="number" id="security-min-password-length" min="6" value="<?php p($_['minPasswordLength']) ?>">
        <button id="save-pass-length" class="save"><?php p($l->t('Save length'));?></button>
        <span id="security-min-password-length-message" class="msg"></span>
	</div>
	<div>
		<input type="checkbox" class="checkbox" id="security-enforce-upper-lower-case"
			<?php if ($_['isUpperLowerCaseEnforced']) p("checked");?> >
		<label for="security-enforce-upper-lower-case"><?php p($l->t('Enforce at least one upper and one lower case character on passwords')) ?></label>
	</div>
	<div>
		<input type="checkbox" class="checkbox" id="security-enforce-numerical-characters"
			<?php if ($_['isNumericalCharsEnforced']) p("checked");?> >
		<label for="security-enforce-numerical-characters"><?php p($l->t('Enforce at least one numerical characters on passwords')) ?></label>
	</div>
	<div>
		<input type="checkbox" class="checkbox" id="security-enforce-special-characters"
			<?php if ($_['isSpecialCharsEnforced']) p("checked");?> >
		<label for="security-enforce-special-characters"><?php p($l->t('Enforce at least one special characters on passwords')) ?></label>
	</div>
</div>