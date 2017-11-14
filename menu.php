<div id="topmenu">

<?php if(isset($loginmenu) && $loginmenu == true) { ?>

	<span class="left">
		<a href="login.php"><button><?php __('Open Vault'); ?></button></a>
		<a href="managevaults.php"><button><?php __('Manage Vaults'); ?></button></a>
	</span>
	<span class="center">
	</span>
	<span class="right">
		<form method="POST" action="lang.php">
			<select name="setlang" onchange="this.form.submit()" title="Change Language">
				<?php
				foreach(scandir("lang") as $file) {
					if(substr($file,0,1) == ".") continue;
					$currentlang = "";
					if(isset($_SESSION['lang']))
						$currentlang = $_SESSION['lang'];
					else
						$currentlang = $defaultlang;
					$selected = "";
					$file = basename($file, ".php");
					if($currentlang == $file) $selected = "selected='true'";
					echo "<option $selected>$file</option>";
				}
				?>
			</select>
		</form>
		<a href="about.php"><button><?php __('About'); ?></button></a>
	</span>

<?php } else { ?>

	<span class="left">
		<?php
			$groupview_param = "groupview=collapsed";
			if((!isset($_GET['groupview'])) || (isset($_GET['groupview']) && $_GET['groupview'] == "collapsed"))
				$groupview_param = "groupview=expanded";
		?>
		<a href="new.php"><button><?php __('New Entry'); ?></button></a>
		<a href="newgroup.php"><button><?php __('New Group'); ?></button></a>
		<a href="index.php?<?php echo $groupview_param; ?>"><button><?php __('Show Entries'); ?></button></a>
	</span>
	<span class="center">
	</span>
	<span class="right">
		<input type="text" id="searchbar" autofocus="true" oninput="search(this.value)" placeholder="<?php __('Search...'); ?>" title="<?php __('Search...'); ?>">
		<a href="login.php?logout=1"><button><?php __('Close Vault'); ?></button></a>
	</span>

<?php } ?>

</div>
<br>
