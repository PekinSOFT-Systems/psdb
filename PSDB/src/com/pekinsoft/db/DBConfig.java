/*
 * Copyright (C) 2006-2021 PekinSOFT Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * *****************************************************************************
 * Class Name: DBConfig.java
 *     Author: Sean Carrick <sean at pekinsoft dot com>
 *    Created: Jan 15 2021
 * 
 *    Purpose:
 * 
 * *****************************************************************************
 * CHANGE LOG:
 * 
 * Date        By                   Reason
 * ----------  -------------------  --------------------------------------------
 * 01/15/2021  Sean Carrick          Initial Creation.
 * *****************************************************************************
 */
package com.pekinsoft.db;

import com.pekinsoft.db.utils.PasswordUtils;
import java.util.Optional;
import java.util.Properties;

/**
 *
 * @author Sean Carrick
 */
public class DBConfig {

    private static final Properties config = new Properties();

    private DBConfig() {
        // Initializing the available properties for the PSDB API.
        config.setProperty("db.name", "sample.db");
        config.setProperty("db.path", System.getProperty("user.home"));
        config.setProperty("db.user", "app");
        config.setProperty("db.password", "app");
        config.setProperty("db.create", "true");
        config.setProperty("db.secure.passwords", "false");
        config.setProperty("db.secure.passwords.length", "10");
        config.setProperty("db.secure.passwords.symbols", "1");
        config.setProperty("db.secure.passwords.numbers", "1");
        config.setProperty("db.secure.passwords.upper", "1");
    }

    /**
     * Retrieves the name of the database. The database name translates to a
     * folder on disk, as determined by the setting {@code getDatabasePath}. The
     * default database name is &quot;sample.db&quot;.
     *
     * @return name of the current database
     */
    public static String getDatabaseName() {
        return config.getProperty("db.name");
    }

    /**
     * Stores the name of the database. The database name translates to a folder
     * on disk, as determined by the setting {@code getDatabasePath}. The
     * default database name is &quot;sample.db&quot;.
     *
     * @param dbName the name for the current database
     */
    public static void setDatabaseName(String dbName) {
        config.setProperty("db.name", dbName);
    }

    /**
     * Retrieves the path of the database on disk. The database path translates
     * to a specific path on the local computer. The default database path is
     * the value returned from the call to
     * {@code System.getProperty("user.home")}, which is the current user's home
     * folder, and that location is system-dependent.
     *
     * @return the path of the current database on disk
     */
    public static String getDatabasePath() {
        return config.getProperty("db.path");
    }

    /**
     * Stores the path of the database on disk. The database path translates to
     * a specific path on the local computer. The default database path is the
     * value returned from the call to {@code System.getProperty("user.home")},
     * which is the current user's home folder, and that location is
     * system-dependent.
     *
     * @param dbPath the path for the current database on disk
     */
    public static void setDatabasePath(String dbPath) {
        config.setProperty("db.path", dbPath);
    }

    /**
     * Retrieves the currently set user name for the database. The user name is
     * used for various functions within the API, such as creating ownership of
     * the database files. The default user name is &quot;APP&quot;
     *
     * @return database user name
     */
    public static String getDatabaseUser() {
        return config.getProperty("db.user");
    }

    /**
     * Stores the currently set user name for the database. The user name is
     * used for various functions within the API, such as creating ownership of
     * the database files. The default user name is &quot;APP&quot;
     *
     * @param dbUser database user name to use
     */
    public static void setDatabaseUser(String dbUser) {
        config.setProperty("db.user", dbUser);
    }

    /**
     * Retrieves the password for the database.
     *
     * @return either the password in <em>clear text</em>, or the password's
     * one-way hash, depending upon the return from {@code isSecurePasswordsOn}.
     */
    public static String getDatabasePassword() {
        return config.getProperty("db.password");
    }

    /**
     * PSDB allows for requiring secure passwords to be used. If the setting
     * {@code isSecurePasswordsOn} returns {@code true}, then the use of secure
     * passwords is enabled. The default settings for using secure passwords are
     * that all passwords must be a minimum of eight (8) characters long, and
     * the must contain at least one lowercase letter, one uppercase letter, one
     * number, and one symbol. The settings for secure passwords can be changed
     * by using one of the secure password setters:
     * <ul>
     * <li>{@code setSecurePasswordSymbolCount(int count)}</li>
     * <li>{@code setSecurePasswordNumberCount(int count)}</li>
     * <li>{@code setSecurePasswordLowerCount(int count)}</li>
     * <li>{@code setSecurePasswordUpperCount(int count)}</li></ul>
     * <p>
     * When the database is set to use secure passwords, the password is not
     * stored in the configuration in plain text. Instead, it is stored as a
     * one-way hash of the password. To determine whether a provided password
     * matches a stored password, you must use the {@code securePasswordMatches}
     * method.</p>
     *
     * @param secret the password for the database
     */
    public static void setDatabasePassword(String secret) {
        // Check to see if we are using secure passwords:
        if (areSecurePasswordsOn()) {
            // Since we are, we need to determine the minimum length of passwords.
            int minPasswordLength = getSecurePasswordLength();
            
            // If provided password is null or does not meet the minimum length,
            //+ we need to eject.
            if (secret == null || !(secret.length() >= minPasswordLength)) {
                throw new IllegalArgumentException("Passwords may not be null or "
                        + "empty.");
            }
            
            int symbolCount = 0;
            int numeralCount = 0;
            int lowercaseCount = 0;
            int uppercaseCount = 0;
            for (int i = 0; i < secret.length(); i++) {
                char c = secret.charAt(i);
                if (Character.isUpperCase(c)) {
                    uppercaseCount++;
                } else if (Character.isLowerCase(c)) {
                    lowercaseCount++;
                } else if (Character.isDigit(c)) {
                    numeralCount++;
                } else if (!Character.isLetterOrDigit(c)) {
                    symbolCount++;
                }
            }

            if (symbolCount < 1) {
                throw new IllegalArgumentException("Passwords must be secure. To "
                        + "achieve this, passwords must contain at least one symbol.");
            } else if (numeralCount < 1) {
                throw new IllegalArgumentException("Passwords must be secure. To "
                        + "achieve this, passwords must contain at least one number.");
            } else if (lowercaseCount < 1) {
                throw new IllegalArgumentException("Passwords must be secure. To "
                        + "achieve this, passwords must contain at least one "
                        + "lowercase letter.");
            } else if (uppercaseCount < 1) {
                throw new IllegalArgumentException("Passwords must be secure. To "
                        + "achieve this, passwords must contain at least one "
                        + "uppercase letter.");
            }

            Optional<String> salt = PasswordUtils.generateSalt(secret.length());
            Optional<String> hash = PasswordUtils.hashPassword(secret, salt.toString());
            config.setProperty("db.password", hash.toString());
        } else {
            config.setProperty("db.password", secret);
        }
    }
    
    /**
     * Creates a secure one-way hash from the provided password and compares it
     * to the stored one-way hash password. This method should only be used when
     * {@code isSecurePasswordsOn() == true}.
     * 
     * @param secret the clear-text password
     * @return {@code true} if the one-way hash of {@code secret} matches the
     *          stored one-way hash; {@code false} otherwise
     */
    public static boolean securePasswordMatches(String secret) {
        // Since this is the secure password test, null or empty passwords do 
        //+ not follow the rules by default, so we need to eject.
        if (secret == null || secret.isBlank() || secret.isEmpty()) {
            return false; // No need for an exception, just return false.
        }
        
        Optional<String> salt = PasswordUtils.generateSalt(secret.length());
        Optional<String> hash = PasswordUtils.hashPassword(secret, salt.toString());
        
        return hash.toString().equals(getDatabasePassword());
    }
    
    /**
     * Checks whether the password provided matches the stored password. This 
     * method should only be used when {@code isSecurePasswordsOn() == false}.
     * The comparison made of the passwords <strong>is</strong> case-sensitive,
     * therefore, &quot;HelloDatabase&quot; and &quot;helloDatabase&quote; will
     * return {@code false}.
     * 
     * @param password the clear-text password
     * @return {@code true} if the clear-text password matches the stored
     *          clear-text password; {@code false} otherwise
     */
    public static boolean passwordMatches(String password) {
        return password.equals(getDatabasePassword());
    }
    
    /**
     * Determines whether the database system is configured to use secure 
     * passwords or not. By using secure passwords, passwords will <strong>never
     * </strong> be stored in clear text, neither in the configuration, nor in
     * the database. If an application developer is making his/her application a
     * multi-user database system and wants to store username/passwords for each
     * user of the system in a database table, turning on secure passwords for
     * that application's instance of the PSDB API will ensure that no passwords
     * are ever stored in clear text. To turn on the secure passwords setting, 
     * call {@code turnOnSecurePasswords()}. To turn off secure passwords, call
     * {@code turnOffSecurePasswords()}.
     * 
     * @return 
     */
    public static boolean areSecurePasswordsOn() {
        return Boolean.parseBoolean(config.getProperty("db.secure.passwords"));
    }
    
    /**
     * By calling this method, secure passwords will be turned on for the 
     * database system for the application using it. This setting only affects
     * the application implementing the PSDB API. A single developer can have
     * multiple applications implementing the PSDB API, each with different
     * configuration settings and the settings of one application will never 
     * interfere with another application, provided that no two applications use
     * the same database.
     * <dl><dt>Warning Regarding this Setting:</dt>
     * <dd>If this setting is turned on at any point after data has been written
     * to a users table in a database, no passwords within that table are 
     * automatically converted. If there are already records in the users table,
     * and a password is already set in the PSDB configuration, they will need 
     * to be manually converted to use the secure passwords functionality.</dd>
     * </dl>
     */
    public static void turnOnSecurePasswords() {
        config.setProperty("db.secure.passwords", "true");
    }
    
    /**
     * By calling this method, secure passwords will be turned off for the 
     * database system for the application using it. This setting only affects
     * the application implementing the PSDB API. A single developer can have
     * multiple applications implementing the PSDB API, each with different
     * configuration settings and the settings of one application will never 
     * interfere with another application, provided that no two applications use
     * the same database.
     * <dl><dt>Warning Regarding this Setting:</dt>
     * <dd>If this setting is turned off at any point after data has been written
     * to a users table in a database, no passwords within that table are 
     * automatically converted. If there are already records in the users table,
     * and a password is already set in the PSDB configuration, they will need 
     * to be manually converted to use the non-secure passwords functionality.
     * </dd></dl>
     * <dl><dt>REMEMBER:</dt><dd>The secure passwords option on the PSDB API uses
     * <strong>one-way</strong> encryption hashes, so there is no way to bring
     * a secure password back to its clear text. If you turn off secure passwords
     * after an application has already created secure password hashes, then all
     * passwords will need to be reset by the users.</dd></dl>
     */
    public static void turnOffSecurePasswords() {
        config.setProperty("db.secure.passwords", "false");
    }
    
    /**
     * Retrieves the current minimum length setting for secure passwords.
     * 
     * @return current minimum password length
     */
    public static int getSecurePasswordLength() {
        return Integer.parseInt(config.getProperty("db.secure.passwords.length"));
    }
    
    /**
     * Sets the minimum length for secure passwords. The default minimum length
     * is 10 characters, so this setting should not be changed to a shorter
     * minimum length. However, PekinSOFT Systems has only stopped the changing
     * of this setting if the minimum length is attempted to be set shorter than
     * 8 characters.
     * <p>
     * Quality secure passwords are typically as long as the user can remember.
     * Furthermore, they contain letters (upper- and lower-case), numbers, and
     * symbols. The minimum number of each of these can also be set using the
     * appropriate setter methods. The greater the minimum length, or number of
     * various character types, the greater the security of the password, and
     * the lesser the likelihood of someone guessing (or cracking) the password.
     * </p>
     * 
     * @param minimum the minimum length of passwords
     */
    public static void setSecurePasswordLength(int minimum) {
        // The default minimum of this setting is 10, so we should compare against
        //+ that and bail if the user is attempting to make it shorter. However,
        //+ we will allow them to make the minimum password minimum shorter than
        //+ the default, but we are going to require it to be at least 8 
        //+ characters in length.
        if (minimum < 8) {
            // User attempting to set the minimum password length to less than
            //+ 8 characters. This would allow not-so-secure passwords, so we 
            //+ need to eject and not allow it to be done.
            throw new IllegalArgumentException("The length for secure passwords"
                    + " should be longer than for normal passwords. The default"
                    + " length is 10, so the provided length should be greater "
                    + "than that, or just leave the default setting.");
        }
        
        config.setProperty("db.secure.passwords.length", String.valueOf(minimum));
    }
    
    /**
     * Retrieves the minimum number of symbols required for a secure password.
     * 
     * @return minimum number of symbols required
     */
    public static int getSecurePasswordSymbolsLength() {
        return Integer.parseInt(config.getProperty("db.secure.passwords.symbols"));
    }
    
    /**
     * Sets the minimum number of symbols required to be used in a secure 
     * password. The more symbols required, the greater the security of the
     * password and the less likelihood of the password being guessed/cracked.
     * 
     * @param minimum the minimum number of symbols required
     */
    public static void setSecurePasswordSymbolsLength(int minimum) {
        // The secure passwords should use symbols to make them more secure. If
        //+ minimum is less than one, we need to eject.
        if (minimum < 1) {
            throw new IllegalArgumentException("The minimum number of symbols "
                    + "in a secure password needs to be greater than zero. The "
                    + "default is 1.");
        }
        
        config.setProperty("db.secure.passwords.symbols", String.valueOf(minimum));
    }
    
    /**
     * Retrieves the minimum number of numbers required for a secure password.
     * 
     * @return the minimum number of numbers required
     */
    public static int getSecurePasswordNumbersLength() {
        return Integer.parseInt(config.getProperty("db.secure.passwords.numbers"));
    }
    
    /**
     * Sets the minimum number of numbers required to be used in a secure
     * password. The more numbers required, the more secure the password is and
     * the less likely it is to be guessed/cracked.
     * 
     * @param minimum the minimum number of numbers required
     */
    public static void setSecurePasswordNumbersLength(int minimum) {
        // The secure passwords should use numbers to make them more secure. If
        //+ minimum is less than one, we need to eject.
        if (minimum < 1) {
            throw new IllegalArgumentException("The minimum number of numbers "
                    + "in a secure password needs to be greater than zero. The "
                    + "default is 1.");
        }
        config.setProperty("db.secure.passwords.numbers", String.valueOf(minimum));
    }
    
    /**
     * Retrieves the minimum number of uppercase characters required in a secure
     * password.
     * 
     * @return the minimum number of uppercase characters required
     */
    public static int getSecurePasswordUppercaseLength() {
        return Integer.parseInt(config.getProperty("db.secure.passwords.upper"));
    }
    
    /**
     * Sets the minimum number of uppercase characters required to be used in a
     * secure password. The more uppercase characters required, the more secure
     * the password is and the less likely it is to be guessed/cracked.
     * 
     * @param minimum the minimum number of uppercase characters required
     */
    public static void setSecurePasswordUppercaseLength(int minimum) {
        // The secure passwords should use uppercase letters, mixed with other
        //+ features, to make them more secure. If the minimum is less than one,
        //+ we need to eject.
        if (minimum < 1) {
            throw new IllegalArgumentException("The minimum number of uppercase "
                    + "letters in a secure password needs to be greater than "
                    + "zero. The default is 1.");
        }
        
        config.setProperty("db.secure.passwords.upper", String.valueOf(minimum));
    }
    
}
