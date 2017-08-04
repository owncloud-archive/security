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
<h2 class="inlineblock"><?php p($l->t('Brute Force Protection')); ?></h2>
<div id="brute-force-protection">
	<div>
		<input type="checkbox" class="checkbox" id="security-brute-force-protection-enabled"
			<?php if ($_['isBruteForceProtectionEnabled']) p("checked");?> >
		<label for="security-brute-force-protection-enabled"><?php p($l->t('Activate Brute Force Protection')) ?></label>
	</div>
</div>
<br>
<h2 class="inlineblock"><?php p($l->t('Password Policy')); ?></h2>
<div id="password-policy">
	<div>
		<label for="security-min-password-length"><?php p($l->t('Determine minimum password length')) ?></label>
		<input type="number" id="security-min-password-length" min="6" value="<?php p($_['minPasswordLength']) ?>">
        <button id="save-pass-length" class="save"><?php p($l->t('Save Length'));?></button>
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