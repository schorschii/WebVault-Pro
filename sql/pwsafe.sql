CREATE TABLE `password` (
  `id` int(11) NOT NULL,
  `vault_id` int(11) NOT NULL,
  `group_id` int(11) DEFAULT NULL,
  `title` text NOT NULL,
  `username` text NOT NULL,
  `password` text NOT NULL,
  `iv` text NOT NULL,
  `description` text,
  `url` text
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `passwordgroup` (
  `id` int(11) NOT NULL,
  `title` text NOT NULL,
  `description` text
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `setting` (
  `id` int(11) NOT NULL,
  `title` text NOT NULL,
  `value` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE `vault` (
  `id` int(11) NOT NULL,
  `title` text NOT NULL,
  `password_test` text NOT NULL,
  `iv_test` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


ALTER TABLE `password`
  ADD PRIMARY KEY (`id`),
  ADD KEY `vault_id` (`vault_id`),
  ADD KEY `group_id` (`group_id`);
ALTER TABLE `passwordgroup`
  ADD PRIMARY KEY (`id`);
ALTER TABLE `vault`
  ADD PRIMARY KEY (`id`);
ALTER TABLE `setting`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `password`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;
ALTER TABLE `passwordgroup`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;
ALTER TABLE `vault`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1;
ALTER TABLE `setting`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `password`
  ADD CONSTRAINT `fk_group` FOREIGN KEY (`group_id`) REFERENCES `passwordgroup` (`id`),
  ADD CONSTRAINT `fk_vault` FOREIGN KEY (`vault_id`) REFERENCES `vault` (`id`);
