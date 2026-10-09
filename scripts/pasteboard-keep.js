// Keep the person's clipboard across an app proof run (scripts/app-proofs.sh): `save FILE` writes
// every item on the general pasteboard, every type with its data, to FILE (a property list);
// `restore FILE` puts exactly those items back. The proofs paste and copy through the general
// pasteboard, which is the person's own: it is put back as it was, red, green or crash.
//
// **A concealed item is never written down**: a clipboard holding a password manager's item
// (org.nspasteboard.ConcealedType or org.nspasteboard.TransientType, nspasteboard.org) makes
// `save` write nothing and exit with "CONCEALED", and the run is refused.
//
//   osascript -l JavaScript scripts/pasteboard-keep.js save FILE
//   osascript -l JavaScript scripts/pasteboard-keep.js restore FILE
ObjC.import('AppKit');

function run(argv) {
    const [mode, file] = argv;
    const board = $.NSPasteboard.generalPasteboard;
    if (mode === 'save') {
        const kept = $.NSMutableArray.array;
        const items = board.pasteboardItems;
        const count = items.isNil() ? 0 : items.count;
        const concealed = ['org.nspasteboard.ConcealedType', 'org.nspasteboard.TransientType'];
        for (let i = 0; i < count; i++) {
            const types = items.objectAtIndex(i).types;
            for (let j = 0; j < types.count; j++) {
                if (concealed.includes(ObjC.unwrap(types.objectAtIndex(j)))) {
                    throw new Error('CONCEALED');
                }
            }
        }
        for (let i = 0; i < count; i++) {
            const item = items.objectAtIndex(i);
            const types = $.NSMutableDictionary.dictionary;
            for (let j = 0; j < item.types.count; j++) {
                const type = item.types.objectAtIndex(j);
                const data = item.dataForType(type);
                if (!data.isNil()) types.setObjectForKey(data, type);
            }
            kept.addObject(types);
        }
        if (!kept.writeToFileAtomically($(file), true)) throw new Error('cannot write ' + file);
        return 'kept ' + kept.count + ' item(s)';
    }
    if (mode === 'restore') {
        const kept = $.NSArray.arrayWithContentsOfFile($(file));
        if (kept.isNil()) throw new Error('nothing kept in ' + file);
        const items = $.NSMutableArray.array;
        for (let i = 0; i < kept.count; i++) {
            const types = kept.objectAtIndex(i);
            const item = $.NSPasteboardItem.alloc.init;
            const keys = types.allKeys;
            for (let j = 0; j < keys.count; j++) {
                const type = keys.objectAtIndex(j);
                item.setDataForType(types.objectForKey(type), type);
            }
            items.addObject(item);
        }
        board.clearContents;
        if (items.count > 0) board.writeObjects(items);
        return 'restored ' + items.count + ' item(s)';
    }
    throw new Error('usage: pasteboard-keep.js save|restore FILE');
}
