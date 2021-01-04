package proto

var Handshake = "Box-Backup:v=C"

const HandshakeLen = 32

// This map contains commands with their responses.
var Commands = map[string][2]uint32{
	"proto.Error":                {0, 0},
	"proto.Version":              {1, 1},
	"proto.Login":                {2, 3},
	"proto.LoginConfirmed":       {3, 0},
	"proto.Finished":             {4, 4},
	"proto.Success":              {5, 0},
	"proto.SetClientStoreMarker": {6, 0},

	"proto.GetObject":     {10, 5},
	"proto.MoveObject":    {11, 0},
	"proto.GetObjectName": {12, 13},
	"proto.ObjectName":    {13, 0},

	"proto.CreateDirectory":     {20, 0},
	"proto.ListDirectory":       {21, 5},
	"proto.ChangeDirAttributes": {22, 0},
	"proto.DeleteDirectory":     {23, 0},
	"proto.UndeleteDirectory":   {24, 0},

	"proto.StoreFile":                    {30, 5},
	"proto.GetFile":                      {31, 5},
	"proto.SetReplacementFileAttributes": {32, 0},
	"proto.DeleteFile":                   {33, 5},
	"proto.GetBlockIndexByID":            {34, 5},
	"proto.GetBlockIndexByName":          {35, 5},
	"proto.UndeleteFile":                 {36, 0},

	"proto.GetAccountUsage":  {40, 41},
	"proto.AccountUsage":     {41, 0},
	"proto.GetIsAlive":       {42, 0},
	"proto.IsAlive":          {43, 0},
	"proto.GetAccountUsage2": {44, 45},
	"proto.AccountUsage2":    {45, 0},

	"proto.CreateDirectory2": {46, 0},
}

var factory = map[uint32]interface{}{
	0: &Error{},
	1: &Version{},
	2: &Login{},
	3: &LoginConfirmed{},
	4: &Finished{},
	5: &Success{},
	6: &SetClientStoreMarker{},

	10: &GetObject{},
	11: &MoveObject{},
	12: &GetObjectName{},
	13: &ObjectName{},

	20: &CreateDirectory{},
	21: &ListDirectory{},
	22: &ChangeDirAttributes{},
	23: &DeleteDirectory{},
	24: &UndeleteDirectory{},

	30: &StoreFile{},
	31: &GetFile{},
	32: &SetReplacementFileAttributes{},
	33: &DeleteFile{},
	34: &GetBlockIndexByID{},
	35: &GetBlockIndexByName{},
	36: &UndeleteFile{},

	40: &GetAccountUsage{},
	41: &AccountUsage{},
	42: &GetIsAlive{},
	43: &IsAlive{},
	44: &GetAccountUsage2{},
	45: &AccountUsage2{},
	46: &CreateDirectory2{},
}

func GetCommand(id uint32) (interface{}, bool) {
	r, ok := factory[id]
	return r, ok
}

type Header struct {
	Size    uint32
	Command uint32
}

const STREAM_TYPE = 0xffffffff

type Error struct {
	Type    int32 // 1000 = error
	SubType int32
}

type Version struct {
	Version int32
}

type Login struct {
	Client int32
	Flags  int32
}

type LoginConfirmed struct {
	ClientStoreMarker int64
	BlocksUsed        int64
	BlocksSoftLimit   int64
	BlocksHardLimit   int64
}

type Finished struct {
}

type Success struct {
	ObjectID int64
}

type SetClientStoreMarker struct {
	ClientStoreMarker int64
}

//
// GetObject
//
// Returns the object (file or directory) in store format, e.g. with file data
// first, followed by block index appended at the end.
// This means that whole encrypted stream needs to be fetched before accessing
// the block index.
//
type GetObject struct {
	ObjectID int64
	// reply has stream following (if successful)
}

//
// The stream contains this header with a magic marker specifying whether this
// is a file or directory.
//
type FileStreamFormat struct {
	// #define OBJECTMAGIC_FILE_MAGIC_VALUE_V1         0x66696C65
	// #define OBJECTMAGIC_DIR_MAGIC_VALUE             0x4449525F
	MagicValue        int32 // also the version number
	NumBlocks         int64 // number of blocks contained in the file
	ContainerID       int64
	ModificationTime  int64
	MaxBlockClearSize int32 // Maximum clear size that can be expected for a block
	Options           int32 // bitmask of options used
	// This is followed by a BackupStoreFilename, which is prefixed by two
	// bytets header.
	// Lower two bits contain encoding (2 - blowfish)
	// Upper bits contain the size of this filename block.
	//
	// Then a BackupClientFileAttributes block follows, prefixed by a 4 byte
	// size header.
}

type FileBlockIndex struct {
	// #define OBJECTMAGIC_FILE_BLOCKS_MAGIC_VALUE_V1 0x62696478
	MagicValue  int32   // different magic value
	OtherFileID int64   // the file ID of the 'other' file which may be referenced by the index
	EntryIVBase [8]byte // base value for block IV
	NumBlocks   int64   // repeat of value in file header
}

//
// FileBlockIndex is followed by the blocks, where each FileBlockIndexEntry is
// prefixed by the 8 byte header, which is either size or a block number in
// another file.
// typedef struct
// {
//         union
//         {
//                 int64_t mEncodedSize;           // size encoded, if > 0
//                 int64_t mOtherBlockIndex;       // 0 - block number in other file, if <= 0
//         };
//         uint8_t mEnEnc[sizeof(file_BlockIndexEntryEnc)]; // Encoded section
// } file_BlockIndexEntry;
type FileBlockIndexEntry struct {
	Size           int32    // size in clear
	WeakChecksum   uint32   // weak, rolling checksum
	StrongChecksum [16]byte //StrongChecksum[MD5Digest::DigestLength] uint8_t
	// strong digest based checksum
}

type MoveObject struct {
	ObjectID          int64
	MoveFromDirectory int64
	MoveToDirectory   int64
	Flags             int32
	// Filename	NewFilename
	// CONSTANT Flags_MoveAllWithSameName			1
	// CONSTANT Flags_AllowMoveOverDeletedObject	2
	// # consider this an object command as, although it deals with directory entries,
	// # it's not specific to either a file or a directory
}

type GetObjectName struct {
	ObjectID              int64
	ContainingDirectoryID int64
	// CONSTANT	ObjectID_DirectoryOnly	0
	// # set ObjectID to ObjectID_DirectoryOnly to only get info on the directory
}

type ObjectName struct {
	NumNameElements  int32
	ModificationTime int64
	AttributesHash   int64
	Flags            int16
	// # NumNameElements is zero if the object doesn't exist
	// CONSTANT	NumNameElements_ObjectDoesntExist	0
	// # a stream of Filename objects follows, if and only if NumNameElements > 0
}

/*-------------------------------------------------------------------------------------
#  Directory commands
# -----------------------------------------------------------------------------------*/
type CreateDirectory struct {
	ContainingDirectoryID int64
	AttributesModTime     int64
	/*
		Filename	DirectoryName
		# stream following containing attributes
	*/
}

type CreateDirectory2 struct {
	ContainingDirectoryID int64
	AttributesModTime     int64
	ModificationTime      int64
	/*
		Filename	DirectoryName
		# stream following containing attributes
	*/
}

type ListDirectory struct {
	ObjectID        int64
	FlagsMustBeSet  int16
	FlagsNotToBeSet int16
	SendAttributes  bool
	/*
		# make sure these flags are synced with those in BackupStoreDirectory
		CONSTANT	Flags_INCLUDE_EVERYTHING 	-1
		CONSTANT	Flags_EXCLUDE_NOTHING 		0
		CONSTANT	Flags_EXCLUDE_EVERYTHING	15
		CONSTANT	Flags_File			1
		CONSTANT	Flags_Dir			2
		CONSTANT	Flags_Deleted			4
		CONSTANT	Flags_OldVersion		8
		# make sure this is the same as in BackupStoreConstants.h
		CONSTANT	RootDirectory			1

		# reply has stream following Success object, containing a stored BackupStoreDirectory
	*/
}

type DirStream struct {
	MagicValue        int32 // also the version number
	NumEntries        int32
	ObjectID          int64 // this object ID
	ContainerID       int64 // ID of container
	AttributesModTime uint64
	OptionsPresent    int32 // bit mask of optional sections / features present
	// Then a StreamableMemBlock for attributes
}

type EntryStream struct {
	ModificationTime uint64
	ObjectID         int64
	SizeInBlocks     int64
	AttributesHash   uint64
	Flags            int16 // order smaller items after bigger ones (for alignment)
	// Then a BackupStoreFilename
	// Then a StreamableMemBlock for attributes
}

// BackupClientFileAttributes
type AttributeStream struct {
	AttributeType        int32
	UID                  uint32
	GID                  uint32
	ModificationTime     uint64
	AttrModificationTime uint64
	UserDefinedFlags     uint32
	FileGenerationNumber uint32
	Mode                 uint16
	// Symbolic link filename may follow
	// Extended attribute (xattr) information may follow, format is:
	//   uint32_t     Size of extended attribute block (excluding this word)
	// For each of NumberOfAttributes (sorted by AttributeName):
	//   uint16_t     AttributeNameLength
	//   char          AttributeName[AttributeNameLength]
	//   uint32_t     AttributeValueLength
	//   unsigned char AttributeValue[AttributeValueLength]
	// AttributeName is 0 terminated, AttributeValue is not (and may be binary data)
}

/*
// This has wire packing so it's compatible across platforms
// Use wider than necessary sizes, just to be careful.
typedef struct
{
        int32_t uid, gid, mode;
        #ifdef WIN32
        int64_t fileCreationTime;
        #endif
} attributeHashData;

typedef struct
{
        int64_t mDependsNewer;
        int64_t mDependsOlder;
} en_StreamFormatDepends;
*/

type ChangeDirAttributes struct {
	ObjectID          int64
	AttributesModTime int64
	// # stream following containing attributes
}

type DeleteDirectory struct {
	ObjectID int64
}

type UndeleteDirectory struct {
	ObjectID int64
	/*
		# may not have exactly the desired effect if files within in have been
		deleted before the directory was deleted.
	*/
}

/*-------------------------------------------------------------------------------------
#  File commands
# -----------------------------------------------------------------------------------*/

type StoreFile struct {
	DirectoryObjectID int64
	ModificationTime  int64
	AttributesHash    int64
	DiffFromFileID    int64 // 0 if the file is not a diff
	/*
		Filename	Filename
		# then send a stream containing the encoded file
	*/
}

type GetFile struct {
	InDirectory int64
	ObjectID    int64
	/*
		# error returned if not a file, or does not exist
		# reply has stream following, containing an encoded file IN STREAM ORDER
		# (use GetObject to get it in file order)
	*/
}

type SetReplacementFileAttributes struct {
	InDirectory    int64
	AttributesHash int64
	// Followed by a filename
	// # stream follows containing attributes
}

type DeleteFile struct {
	InDirectory int64
	/*
		Filename	Filename
		# will return 0 if the object couldn't be found in the specified directory
	*/
}

type GetBlockIndexByID struct {
	ObjectID int64
	/*
		# stream of the block index follows the reply
		# returns an error if the object didn't exist
	*/
}

type GetBlockIndexByName struct {
	InDirectory int64
	// Followed by a filename
	// Success object contains the found ID -- or 0 if the entry wasn't found in the directory
	// stream of the block index follows the reply if found ID != 0
}

type UndeleteFile struct {
	InDirectory int64
	ObjectID    int64
	// # will return 0 if the object couldn't be found in the specified directory
}

/*-------------------------------------------------------------------------------------
#  Information commands
# -----------------------------------------------------------------------------------*/

type GetAccountUsage struct {
	// # no data members
}

type AccountUsage struct {
	BlocksUsed           int64
	BlocksInOldFiles     int64
	BlocksInDeletedFiles int64
	BlocksInDirectories  int64
	BlocksSoftLimit      int64
	BlocksHardLimit      int64
	BlockSize            int32
}

type GetIsAlive struct {
	// # no data members
}

type IsAlive struct {
	// # no data members
}

type GetAccountUsage2 struct {
	// # no data members
}

type AccountUsage2 struct {
	//String	AccountName
	Padding              uint32 // maybe number of accounts?
	AccountEnabled       bool
	ClientStoreMarker    int64
	BlockSize            int32
	LastObjectIDUsed     int64
	BlocksUsed           int64
	BlocksInCurrentFiles int64
	BlocksInOldFiles     int64
	BlocksInDeletedFiles int64
	BlocksInDirectories  int64
	BlocksSoftLimit      int64
	BlocksHardLimit      int64
	NumCurrentFiles      int64
	NumOldFiles          int64
	NumDeletedFiles      int64
	NumDirectories       int64
}
