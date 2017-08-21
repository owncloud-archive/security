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
script('security', 'settings-personal');
style('security', 'settings-personal');
?>
<div id="password-policies" class="hidden">
	<?php print_unescaped(
		"<p>". $l->t('Passwords must:'). "</p>");?>
	<ul class="pass-info">
		<?php print_unescaped(
			"<li class='pass-info-element'>". $l->t('be at least %s characters long ', $_['minPasswordLength']). "</li>");?>
		<?php if ($_['isUpperLowerCaseEnforced']) print_unescaped(
			"<li class='pass-info-element'>". $l->t('contain at least one uppercase letter and at least one lowercase letter '). "</li>");?>
		<?php if ($_['isNumericalCharsEnforced']) print_unescaped(
			"<li class='pass-info-element'>". $l->t('contain at least one numerical character'). "</li>");?>
		<?php if ($_['isSpecialCharsEnforced']) print_unescaped(
			"<li class='pass-info-element'>". $l->t('contain at least one special character'). "</li>");?>
	</ul>
</div>
