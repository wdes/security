'use strict';

/**
 * @param {string[]} modifiedFiles The modified files
 * @returns {string} The commit message
 */
const commitMessage = function (modifiedFiles) {
    return 'update: 🤖 Some updates 🤖';
};

/**
 * @param {string[]} modifiedFiles The modified files
 * @returns {string} The pr message
 */
const prMessage = function (modifiedFiles) {
    return '🤖 Some updates to review 🤖';
};

/**
 * @param {string[]} modifiedFiles The modified files
 * @returns {string} The pr content
 */
const prContent = function (modifiedFiles) {
    let message =
        'Dear human 🌻🐓🦃🦎🦙🐂🐏🐐🐎🦉, after running my task the following file' +
        (modifiedFiles.length > 1 ? 's where updated:' : ' was updated:') +
        '\n';
    message += modifiedFiles
        .map((file) => {
            let emoji = '👽';
            if (file.match(/.(txt)$/g)) {
                emoji = '📦';
            }
            return '- `' + file + '` ' + emoji + '\n';
        })
        .join('');
    return message;
};

/**
 * @param {string[]} modifiedFiles The modified files
 * @returns {string} The pr branch
 */
const prBranch = function (modifiedFiles) {
    return 'refs/heads/update/' + new Date().getTime();
};

module.exports = {
    commitMessage: commitMessage,
    prMessage: prMessage,
    prContent: prContent,
    prBranch: prBranch,
};
