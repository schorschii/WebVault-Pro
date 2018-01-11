--
-- Datenbank: `pwsafe`
--
CREATE TABLE `password` (
  `id` int(11) NOT NULL,
  `vault_id` int(11) NOT NULL,
  `group_id` int(11) DEFAULT NULL,
  `title` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `username` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `password` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `iv` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `url` text CHARACTER SET utf8 COLLATE utf8_unicode_ci
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
CREATE TABLE `passwordgroup` (
  `id` int(11) NOT NULL,
  `vault_id` int(11) NOT NULL,
  `title` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `superior_group_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
CREATE TABLE `setting` (
  `id` int(11) NOT NULL,
  `title` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `value` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
CREATE TABLE `vault` (
  `id` int(11) NOT NULL,
  `title` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `password` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Indizes der exportierten Tabellen
--
ALTER TABLE `password`
  ADD PRIMARY KEY (`id`),
  ADD KEY `vault_id` (`vault_id`),
  ADD KEY `group_id` (`group_id`);
ALTER TABLE `passwordgroup`
  ADD PRIMARY KEY (`id`),
  ADD KEY `vault_id` (`vault_id`);
ALTER TABLE `setting`
  ADD PRIMARY KEY (`id`);
ALTER TABLE `vault`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT für exportierte Tabellen
--
ALTER TABLE `password`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;
ALTER TABLE `passwordgroup`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;
ALTER TABLE `setting`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;
ALTER TABLE `vault`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;
--
-- Constraints der exportierten Tabellen
--

ALTER TABLE `password`
  ADD CONSTRAINT `fk_group` FOREIGN KEY (`group_id`) REFERENCES `passwordgroup` (`id`),
  ADD CONSTRAINT `fk_vault` FOREIGN KEY (`vault_id`) REFERENCES `vault` (`id`);

ALTER TABLE `passwordgroup`
  ADD CONSTRAINT `fk_vault_group` FOREIGN KEY (`vault_id`) REFERENCES `vault` (`id`);
