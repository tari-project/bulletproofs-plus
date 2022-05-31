// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

const VERSION_REGEXP = /^version\s*=\s*"([^"]+)"/m;

const readVersion = function (contents) {
    const matches = contents.match(VERSION_REGEXP);
    if (!matches) {
        throw new Error("Version key not found!");
    }
    return matches[1];
}

const writeVersion = function (contents, version) {
    return contents.replace(VERSION_REGEXP, `version = "${version}"`);
}

module.exports = {readVersion, writeVersion};
