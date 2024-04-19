SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Tabellenstruktur für Tabelle `password`
--

CREATE TABLE `password` (
  `id` int(11) NOT NULL,
  `password_group_id` int(11) DEFAULT NULL,
  `secret` text NOT NULL,
  `aes_iv` tinytext NOT NULL,
  `revision` int(11) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `password_user`
--

CREATE TABLE `password_user` (
  `password_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `aes_key` text NOT NULL,
  `rsa_iv` tinytext NOT NULL,
  `created` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `password_group`
--

CREATE TABLE `password_group` (
  `id` int(11) NOT NULL,
  `parent_password_group_id` int(11) DEFAULT NULL,
  `title` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `share_password_group_user`
--

CREATE TABLE `share_password_group_user` (
  `password_group_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `permission` tinyint(4) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `share_password_group_user_group`
--

CREATE TABLE `share_password_group_user_group` (
  `password_group_id` int(11) NOT NULL,
  `user_group_id` int(11) NOT NULL,
  `permission` tinyint(4) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `share_password_user`
--

CREATE TABLE `share_password_user` (
  `password_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `permission` tinyint(4) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `share_password_user_group`
--

CREATE TABLE `share_password_user_group` (
  `password_id` int(11) NOT NULL,
  `user_group_id` int(11) NOT NULL,
  `permission` tinyint(4) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `user`
--

CREATE TABLE `user` (
  `id` int(11) NOT NULL,
  `uid` text DEFAULT NULL,
  `ldap` int(11) DEFAULT NULL,
  `username` varchar(250) NOT NULL,
  `password` text DEFAULT NULL,
  `display_name` text DEFAULT NULL,
  `email` text DEFAULT NULL,
  `description` text DEFAULT NULL,
  `locked` tinyint(4) NOT NULL DEFAULT 0,
  `public_key` text DEFAULT NULL,
  `private_key` text DEFAULT NULL,
  `salt` text DEFAULT NULL,
  `iv` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `user_group`
--

CREATE TABLE `user_group` (
  `id` int(11) NOT NULL,
  `guid` text DEFAULT NULL,
  `title` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `user_group_member`
--

CREATE TABLE `user_group_member` (
  `user_id` int(11) NOT NULL,
  `user_group_id` int(11) NOT NULL,
  `permission` tinyint(4) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indizes der exportierten Tabellen
--

--
-- Indizes für die Tabelle `password`
--
ALTER TABLE `password`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_password_group` (`password_group_id`);

--
-- Indizes für die Tabelle `password_user`
--
ALTER TABLE `password_user`
  ADD PRIMARY KEY (`password_id`,`user_id`),
  ADD KEY `password_id` (`password_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indizes für die Tabelle `password_group`
--
ALTER TABLE `password_group`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_pg_password_group` (`parent_password_group_id`);

--
-- Indizes für die Tabelle `share_password_group_user`
--
ALTER TABLE `share_password_group_user`
  ADD PRIMARY KEY (`password_group_id`,`user_id`),
  ADD KEY `fk_spgu_user` (`user_id`);

--
-- Indizes für die Tabelle `share_password_group_user_group`
--
ALTER TABLE `share_password_group_user_group`
  ADD PRIMARY KEY (`password_group_id`,`user_group_id`),
  ADD KEY `fk_spgug_user_group` (`user_group_id`);

--
-- Indizes für die Tabelle `share_password_user`
--
ALTER TABLE `share_password_user`
  ADD PRIMARY KEY (`password_id`,`user_id`),
  ADD KEY `fk_spu_user` (`user_id`);

--
-- Indizes für die Tabelle `share_password_user_group`
--
ALTER TABLE `share_password_user_group`
  ADD PRIMARY KEY (`password_id`,`user_group_id`),
  ADD KEY `fk_spug_user_group` (`user_group_id`);

--
-- Indizes für die Tabelle `user`
--
ALTER TABLE `user`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indizes für die Tabelle `user_group`
--
ALTER TABLE `user_group`
  ADD PRIMARY KEY (`id`);

--
-- Indizes für die Tabelle `user_group_member`
--
ALTER TABLE `user_group_member`
  ADD PRIMARY KEY (`user_id`,`user_group_id`),
  ADD KEY `fk_user_group` (`user_group_id`);

--
-- AUTO_INCREMENT für exportierte Tabellen
--

--
-- AUTO_INCREMENT für Tabelle `password`
--
ALTER TABLE `password`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `password_group`
--
ALTER TABLE `password_group`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `user`
--
ALTER TABLE `user`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `user_group`
--
ALTER TABLE `user_group`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Constraints der exportierten Tabellen
--

--
-- Constraints der Tabelle `password`
--
ALTER TABLE `password`
  ADD CONSTRAINT `fk_password_group` FOREIGN KEY (`password_group_id`) REFERENCES `password_group` (`id`);

--
-- Constraints der Tabelle `password_user`
--
ALTER TABLE `password_user`
  ADD CONSTRAINT `fk_password` FOREIGN KEY (`password_id`) REFERENCES `password` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints der Tabelle `password_group`
--
ALTER TABLE `password_group`
  ADD CONSTRAINT `fk_pg_password_group` FOREIGN KEY (`parent_password_group_id`) REFERENCES `password_group` (`id`);

--
-- Constraints der Tabelle `share_password_group_user`
--
ALTER TABLE `share_password_group_user`
  ADD CONSTRAINT `fk_spgu_password_group` FOREIGN KEY (`password_group_id`) REFERENCES `password_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_spgu_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints der Tabelle `share_password_group_user_group`
--
ALTER TABLE `share_password_group_user_group`
  ADD CONSTRAINT `fk_spgug_password_group` FOREIGN KEY (`password_group_id`) REFERENCES `password_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_spgug_user_group` FOREIGN KEY (`user_group_id`) REFERENCES `user_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints der Tabelle `share_password_user`
--
ALTER TABLE `share_password_user`
  ADD CONSTRAINT `fk_spu_password` FOREIGN KEY (`password_id`) REFERENCES `password` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_spu_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints der Tabelle `share_password_user_group`
--
ALTER TABLE `share_password_user_group`
  ADD CONSTRAINT `fk_spug_password` FOREIGN KEY (`password_id`) REFERENCES `password` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_spug_user_group` FOREIGN KEY (`user_group_id`) REFERENCES `user_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints der Tabelle `user_group_member`
--
ALTER TABLE `user_group_member`
  ADD CONSTRAINT `fk_user_2` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`),
  ADD CONSTRAINT `fk_user_group` FOREIGN KEY (`user_group_id`) REFERENCES `user_group` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
