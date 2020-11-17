package bdls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"io"
	mrand "math/rand"
	"testing"
	"time"

	proto "github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func createRoundChangeMessage(t *testing.T, height uint64, round uint64) (*Message, *SignedProto, *ecdsa.PrivateKey) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)
	// key generation
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)
	return createRoundChangeMessageSigner(t, height, round, state, privateKey)
}

func createRoundChangeMessageState(t *testing.T, height uint64, round uint64, state State) (*Message, *SignedProto, *ecdsa.PrivateKey) {
	// key generation
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)
	return createRoundChangeMessageSigner(t, height, round, state, privateKey)
}

//  createRoundChangeMessage generates a random valid <roundchange> message
func createRoundChangeMessageSigner(t testing.TB, height uint64, round uint64, state State, signer *ecdsa.PrivateKey) (*Message, *SignedProto, *ecdsa.PrivateKey) {
	// <roundchange>
	rc := new(Message)
	rc.Type = MessageType_RoundChange
	rc.Height = height
	rc.Round = round
	rc.State = state

	// sign
	signedRc := new(SignedProto)
	signedRc.Sign(rc, signer)

	return rc, signedRc, signer
}

// createCommitMessage generates a random valid <commit> message
func createCommitMessageSigner(t *testing.T, height uint64, round uint64, state State, signer *ecdsa.PrivateKey) (*Message, *SignedProto, *ecdsa.PrivateKey) {
	// <roundchange>
	rc := new(Message)
	rc.Type = MessageType_Commit
	rc.Height = height
	rc.Round = round
	rc.State = state

	signedRc := new(SignedProto)
	signedRc.Sign(rc, signer)

	return rc, signedRc, signer
}

// createCommitMessage generates a random valid <commit> message
func createCommitMessage(t *testing.T, height uint64, round uint64, state State) (*Message, *SignedProto, *ecdsa.PrivateKey) {
	// key generation
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)
	return createCommitMessageSigner(t, height, round, state, privateKey)
}

func createLockReleaseMessage(t *testing.T, numProofs int, height uint64, round uint64, proofHeight uint64, proofRound uint64) (*Message, *SignedProto, *ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	_, signed, priv, pub := createLockMessage(t, numProofs, height, round, proofHeight, proofRound)
	// <lock-release> message
	lockrelease := new(Message)
	lockrelease.Type = MessageType_LockRelease
	lockrelease.LockRelease = signed

	signedlockrelease := new(SignedProto)
	signedlockrelease.Sign(lockrelease, priv)

	return lockrelease, signedlockrelease, priv, pub
}

func createLockMessageState(t *testing.T, numProofs int, state []byte, height uint64, round uint64, proofHeight uint64, proofRound uint64) (*Message, *SignedProto, *ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	valid := 2*((numProofs-1)/3) + 1

	// <lock>
	m := new(Message)
	m.Type = MessageType_Lock
	m.Height = height
	m.Round = round
	m.State = state

	var publicKeys []*ecdsa.PublicKey
	for i := 0; i < numProofs; i++ {
		// <roundchange>
		var signedRc *SignedProto
		var proofKey *ecdsa.PrivateKey
		if i >= valid { // only provide valid proofs
			randstate := make([]byte, 1024)
			_, err := io.ReadFull(rand.Reader, randstate)
			assert.Nil(t, err)
			_, signedRc, proofKey = createRoundChangeMessageState(t, proofHeight, proofRound, randstate)
		} else {
			if i == 0 { // signed the first proof with message's key
				_, signedRc, proofKey = createRoundChangeMessageSigner(t, proofHeight, proofRound, state, privateKey)
			} else {
				_, signedRc, proofKey = createRoundChangeMessageState(t, proofHeight, proofRound, state)
			}
		}
		m.Proof = append(m.Proof, signedRc)
		publicKeys = append(publicKeys, &proofKey.PublicKey)
	}

	signed := new(SignedProto)
	signed.Sign(m, privateKey)

	return m, signed, privateKey, publicKeys

}

// createLockMessage generates a valid lock message, proofs are generated based on quorum,
// the first 2t+1 roundchange proposals are the same
func createLockMessage(t *testing.T, numProofs int, height uint64, round uint64, proofHeight uint64, proofRound uint64) (*Message, *SignedProto, *ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)
	return createLockMessageState(t, numProofs, state, height, round, proofHeight, proofRound)
}

// createSelectMessage creates a valid select message, and generate proofs based on quorum,
// the all roundchange proposals are random and the first proof is signed by message's signer
func createSelectMessage(t *testing.T, numProofs int, height uint64, round uint64, proofHeight uint64, proofRound uint64) (*Message, *SignedProto, *ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	// signer's key
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	// <select>
	m := new(Message)
	m.Type = MessageType_Select
	m.Height = height
	m.Round = round

	var publicKeys []*ecdsa.PublicKey
	for i := 0; i < numProofs; i++ {
		randstate := make([]byte, 1024)
		_, err := io.ReadFull(rand.Reader, randstate)
		assert.Nil(t, err)
		if i == 0 {
			m.State = randstate
		}

		// the comparison function, to make sure m.State is valid
		if bytes.Compare(m.State, randstate) < 0 {
			m.State = randstate
		}

		// <roundchange>
		var signedRc *SignedProto
		var proofKey *ecdsa.PrivateKey

		// the first proof is signed by this message creator
		if i == 0 {
			_, signedRc, proofKey = createRoundChangeMessageSigner(t, proofHeight, proofRound, randstate, privateKey)
		} else {
			_, signedRc, proofKey = createRoundChangeMessageState(t, proofHeight, proofRound, randstate)
		}
		m.Proof = append(m.Proof, signedRc)
		publicKeys = append(publicKeys, &proofKey.PublicKey)
	}

	signed := new(SignedProto)
	signed.Sign(m, privateKey)

	return m, signed, privateKey, publicKeys
}

// createDecideMessage creates a valid <decide> message, and generate <commit> proofs based on quorum,
// the first 2t+1 roundchange proposals are the same
func createDecideMessage(t *testing.T, numProofs int, height uint64, round uint64, proofHeight uint64, proofRound uint64) (*Message, *SignedProto, *ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)
	valid := 2*((numProofs-1)/3) + 1
	state := make([]byte, 1024)
	//_, err := io.ReadFull(rand.Reader, state)
	//assert.Nil(t, err)

	// <lock>
	m := new(Message)
	m.Type = MessageType_Decide
	m.Height = height
	m.Round = round
	m.State = state

	var publicKeys []*ecdsa.PublicKey
	for i := 0; i < numProofs; i++ {
		// <roundchange>
		var signedRc *SignedProto
		var proofKey *ecdsa.PrivateKey
		if i >= valid { // only provide valid proofs
			randstate := make([]byte, 1024)
			_, err := io.ReadFull(rand.Reader, randstate)
			assert.Nil(t, err)
			_, signedRc, proofKey = createCommitMessage(t, proofHeight, proofRound, randstate)
		} else {
			if i == 0 {
				_, signedRc, proofKey = createCommitMessageSigner(t, proofHeight, proofRound, state, privateKey)
			} else {
				_, signedRc, proofKey = createCommitMessage(t, proofHeight, proofRound, state)
			}
		}
		m.Proof = append(m.Proof, signedRc)
		publicKeys = append(publicKeys, &proofKey.PublicKey)
	}

	signed := new(SignedProto)
	signed.Sign(m, privateKey)

	return m, signed, privateKey, publicKeys
}

///////////////////////////////////////////////////////////////////////////////
//
// common message related tests
//
///////////////////////////////////////////////////////////////////////////////
func TestVerifyMessage(t *testing.T) {
	// signer
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	// create consensus
	consensus := createConsensus(t, 0, 0, []*ecdsa.PublicKey{&privateKey.PublicKey})

	// verify nil message
	_, err = consensus.verifyMessage(nil)
	assert.Equal(t, ErrMessageIsEmpty, err)

	// check correctly signed message by a participant
	message := Message{}
	sp := new(SignedProto)
	sp.Sign(&message, privateKey)
	_, err = consensus.verifyMessage(sp)
	assert.Nil(t, err)

	// change signature to random to verify incorrect signature
	_, _ = io.ReadFull(rand.Reader, sp.R)
	_, _ = io.ReadFull(rand.Reader, sp.S)
	_, err = consensus.verifyMessage(sp)
	assert.Equal(t, ErrMessageSignature, err)

	// check bad Message with correct signer
	noise := make([]byte, 1024)
	_, _ = io.ReadFull(rand.Reader, noise)
	// hash message
	sp.Message = noise
	sp.X.Unmarshal(privateKey.PublicKey.X.Bytes())
	sp.Y.Unmarshal(privateKey.PublicKey.Y.Bytes())
	hash := sp.Hash()

	// sign the message
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		panic(err)
	}
	sp.R = r.Bytes()
	sp.S = s.Bytes()

	// unexpected EOF
	_, err = consensus.verifyMessage(sp)
	assert.NotNil(t, err)
}

func TestVerifyMessageUnknownVersion(t *testing.T) {
	// signer
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	// create consensus
	consensus := createConsensus(t, 0, 0, nil)

	// mock Message
	message := Message{}
	sp := new(SignedProto)
	bts, err := proto.Marshal(&message)
	if err != nil {
		panic(err)
	}
	// hash message
	sp.Version = uint32(mrand.Int31()%100 + 10)
	sp.Message = bts
	sp.X.Unmarshal(privateKey.PublicKey.X.Bytes())
	sp.Y.Unmarshal(privateKey.PublicKey.Y.Bytes())
	hash := sp.Hash()

	// sign the message
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		panic(err)
	}
	sp.R = r.Bytes()
	sp.S = s.Bytes()

	bts, err = proto.Marshal(sp)
	assert.Nil(t, err)
	err = consensus.ReceiveMessage(bts, time.Now())
	assert.Equal(t, ErrMessageVersion, err)
}

func TestVerifyMessageUnknownType(t *testing.T) {
	// signer
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	// create consensus
	consensus := createConsensus(t, 0, 0, []*ecdsa.PublicKey{&privateKey.PublicKey})
	message := Message{}
	message.Type = MessageType(mrand.Int31()%100 + 10)

	// check correctly signed message
	sp := new(SignedProto)
	sp.Sign(&message, privateKey)
	bts, err := proto.Marshal(sp)
	assert.Nil(t, err)
	err = consensus.ReceiveMessage(bts, time.Now())
	assert.Equal(t, ErrMessageUnknownMessageType, err)
}

func TestVerifyMessageUnknownParticipant(t *testing.T) {
	// signer
	privateKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)

	// create consensus
	consensus := createConsensus(t, 0, 0, nil)
	message := Message{}
	sp := new(SignedProto)
	sp.Sign(&message, privateKey)

	_, err = consensus.verifyMessage(sp)
	assert.Equal(t, ErrMessageUnknownParticipant, err)
}

///////////////////////////////////////////////////////////////////////////////
//
// <roundchange> message related tests
//
///////////////////////////////////////////////////////////////////////////////
func TestVerifyRoundChangeMessageCorrect(t *testing.T) {
	m, _, privateKey := createRoundChangeMessage(t, 10, 10)
	consensus := createConsensus(t, 9, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})
	err := consensus.verifyRoundChangeMessage(m)
	assert.Nil(t, err)
}

func TestVerifyRoundChangeMessageHeight(t *testing.T) {
	m, _, privateKey := createRoundChangeMessage(t, 20, 10)
	consensus := createConsensus(t, 10, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})
	err := consensus.verifyRoundChangeMessage(m)
	assert.Equal(t, ErrRoundChangeHeightMismatch, err)
}

func TestVerifyRoundChangeMessageRound(t *testing.T) {
	m, _, privateKey := createRoundChangeMessage(t, 20, 9)
	consensus := createConsensus(t, 19, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})
	err := consensus.verifyRoundChangeMessage(m)
	assert.Equal(t, ErrRoundChangeRoundLower, err)
}

///////////////////////////////////////////////////////////////////////////////
//
// <lock> message related tests
//
///////////////////////////////////////////////////////////////////////////////
func TestVerifyLockMessageCorrect(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 9, 10, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Nil(t, err)
}

func TestVerifyLockMessageHeight(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 10, 10, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockHeightMismatch, err)
}

func TestVerifyLockMessageRound(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 1, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockRoundLower, err)
}

func TestVerifyLockMessageStateNil(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessageState(t, 20, nil, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockEmptyState, err)
}

func TestVerifyLockMessageNotSignedByLeader(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 0, 1, 0)
	_ = privateKey
	consensus := createConsensus(t, 0, 0, proofKeys)

	// set a random leader
	randKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)
	consensus.SetLeader(&randKey.PublicKey)

	err = consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockNotSignedByLeader, err)
}

func TestVerifyLockMessageProofSignature(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// random replace with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	_, _ = io.ReadFull(rand.Reader, m.Proof[i].R)
	_, _ = io.ReadFull(rand.Reader, m.Proof[i].S)
	// re-sign the sp with a incorrectly signed proof
	sp.Sign(m, privateKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrMessageSignature, err)
}

func TestVerifyLockMessageProofType(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof with incorrect type
	proof, signedProof, proofKey := createRoundChangeMessageState(t, 1, 0, m.State)
	proof.Type = MessageType_Lock
	signedProof.Sign(proof, proofKey)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockProofTypeMismatch, err)
}

func TestVerifyLockMessageProofHeight(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof with incorrect height
	_, signedProof, proofKey := createRoundChangeMessageState(t, uint64(mrand.Int31n(100000)+100), 0, m.State)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockProofHeightMismatch, err)
}

func TestVerifyLockMessageProofRound(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof with incorrect round
	_, signedProof, proofKey := createRoundChangeMessageState(t, 1, uint64(mrand.Int31n(100000)+100), m.State)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockProofRoundMismatch, err)
}

func TestVerifyLockMessageUnknownParticipant(t *testing.T) {
	m, sp, privateKey, proofKeys := createLockMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof with incorrect round, but do not add to participants
	_, signedProof, _ := createRoundChangeMessageState(t, 1, 0, m.State)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockProofUnknownParticipant, err)
}

func TestVerifyLockMessageProofInsufficient(t *testing.T) {
	quorum := 20
	m, sp, privateKey, proofKeys := createLockMessage(t, quorum, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// only keep 20 participants,by removing the consensus's own public key
	consensus.participants = consensus.participants[1:]
	assert.Equal(t, quorum, len(consensus.participants))

	// random remove a valid proof from the first 2t+1(B)
	valid := 2*((quorum-1)/3) + 1
	i := mrand.Int() % valid
	t.Log(i)
	copy(m.Proof[i:], m.Proof[i+1:])
	m.Proof = m.Proof[:len(m.Proof)-1]
	t.Log(valid, len(m.Proof))
	// re-sign the sp
	sp.Sign(m, privateKey)

	err := consensus.verifyLockMessage(m, sp)
	assert.Equal(t, ErrLockProofInsufficient, err)
}

///////////////////////////////////////////////////////////////////////////////
//
// <select> message related tests
//
///////////////////////////////////////////////////////////////////////////////
func TestVerifySelectMessageCorrect(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 9, 10, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Nil(t, err)
}

func TestVerifySelectMessageHeight(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 10, 10, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectHeightMismatch, err)
}

func TestVerifySelectMessageRound(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 9, 11, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectRoundLower, err)
}

func TestVerifySelectMessageNotSignedByLeader(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	_ = privateKey
	consensus := createConsensus(t, 0, 0, proofKeys)

	// set a random leader
	randKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)
	consensus.SetLeader(&randKey.PublicKey)

	err = consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectNotSignedByLeader, err)
}

func TestVerifySelectMessageProofSignature(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// random replace with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	_, _ = io.ReadFull(rand.Reader, m.Proof[i].R)
	_, _ = io.ReadFull(rand.Reader, m.Proof[i].S)
	// re-sign the sp with a incorrectly signed proof
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrMessageSignature, err)
}

func TestVerifySelectMessageProofType(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof with incorrect type
	proof, signedProof, proofKey := createRoundChangeMessageState(t, 1, 0, m.State)
	proof.Type = MessageType_Lock
	signedProof.Sign(proof, proofKey)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectProofTypeMismatch, err)
}

func TestVerifySelectMessageProofHeight(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof with incorrect height
	_, signedProof, proofKey := createRoundChangeMessageState(t, uint64(mrand.Int31n(100000)+100), 0, m.State)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectProofHeightMismatch, err)
}

func TestVerifySelectMessageProofRound(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof with incorrect round
	_, signedProof, proofKey := createRoundChangeMessageState(t, 1, uint64(mrand.Int31n(100000)+100), m.State)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectProofRoundMismatch, err)
}

func TestVerifySelectMessageProofUnknownParticipant(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// create a signed random proof from unknown participant
	_, signedProof, _ := createRoundChangeMessageState(t, 1, 0, m.State)

	// random replacement with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectProofUnknownParticipant, err)
}

func TestVerifySelectMessageProofInsufficient(t *testing.T) {
	quorum := 20
	m, sp, privateKey, proofKeys := createSelectMessage(t, quorum, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// only keep 20 participants,by removing the consensus's own public key
	consensus.participants = consensus.participants[1:]
	assert.Equal(t, quorum, len(consensus.participants))

	// only keep 2t messages which is less than 2t+1
	valid := 2 * ((quorum - 1) / 3)
	m.Proof = m.Proof[:valid]
	t.Log(valid, len(m.Proof))
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectProofInsufficient, err)
}

func TestVerifySelectMessageMaximalState(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// replace m.State with 0-filled content, which is the minimal one
	m.State = make([]byte, 1024)
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectProofNotTheMaximal, err)
}

func TestVerifySelectMessageStateNilProofNotNil(t *testing.T) {
	m, sp, privateKey, proofKeys := createSelectMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// replace m.State with 0 content, which is the minimal one
	m.State = nil
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectStateMismatch, err)
}

func TestVerifySelectMessageProofExceed(t *testing.T) {
	const quorum = 20
	m, sp, privateKey, proofKeys := createSelectMessage(t, quorum, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	valid := 2*((quorum-1)/3) + 1
	// clear first 2t+1 participants and messages
	consensus.participants = consensus.participants[valid:]
	m.Proof = m.Proof[valid:]

	// append new 2t+1 proof to B' and set new participants
	for i := 0; i < valid; i++ {
		_, signedRc, proofKey := createRoundChangeMessageState(t, 1, 0, m.State)
		m.Proof = append(m.Proof, signedRc)
		consensus.AddParticipant(&proofKey.PublicKey)
	}
	// re-sign the message
	m.Type = MessageType_Select
	sp.Sign(m, privateKey)

	err := consensus.verifySelectMessage(m, sp)
	assert.Equal(t, ErrSelectProofExceeded, err)
}

///////////////////////////////////////////////////////////////////////////////
//
// <lock-release> message related tests
//
///////////////////////////////////////////////////////////////////////////////
func TestVerifyLockReleaseMessageValid(t *testing.T) {
	quorum := 20
	// lock-release message only cares about it's LockRelease fields
	_, sp, _, proofKeys := createLockMessage(t, quorum, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	// remove consensus' publickey to keep quorum participants
	consensus.participants = consensus.participants[1:]
	assert.Equal(t, quorum, len(consensus.participants))

	// set status
	consensus.currentRound.Stage = stageLockRelease
	msg, err := consensus.verifyLockReleaseMessage(sp)
	assert.Nil(t, err)
	assert.NotNil(t, msg)
}

func TestVerifyLockReleaseMessageStatusInValid(t *testing.T) {
	quorum := 20
	_, sp, _, proofKeys := createLockMessage(t, quorum, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	// remove consensus' public key to keep quorum participants
	consensus.participants = consensus.participants[1:]
	assert.Equal(t, quorum, len(consensus.participants))

	msg, err := consensus.verifyLockReleaseMessage(sp)
	assert.Equal(t, ErrLockReleaseStatus, err)
	assert.Nil(t, msg)
}

///////////////////////////////////////////////////////////////////////////////
//
// <commit> message related tests
//
///////////////////////////////////////////////////////////////////////////////
func TestVerifyCommitMessageCorrect(t *testing.T) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	m, _, privateKey := createCommitMessage(t, 10, 10, state)
	consensus := createConsensus(t, 9, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})

	// set stage & locked state for verify incoming <commit>
	consensus.currentRound.Stage = stageCommit
	consensus.currentRound.LockedState = state
	consensus.currentRound.LockedStateHash = consensus.stateHash(state)

	err = consensus.verifyCommitMessage(m)
	assert.Nil(t, err)
}

func TestVerifyCommitMessageState(t *testing.T) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	m, _, privateKey := createCommitMessage(t, 10, 10, nil)
	consensus := createConsensus(t, 9, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})

	// set stage
	consensus.currentRound.Stage = stageCommit

	err = consensus.verifyCommitMessage(m)
	assert.Equal(t, ErrCommitEmptyState, err)
}

func TestVerifyCommitMessageHeight(t *testing.T) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	m, _, privateKey := createCommitMessage(t, 1, 10, state)
	consensus := createConsensus(t, 9, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})

	// set stage
	consensus.currentRound.Stage = stageCommit

	err = consensus.verifyCommitMessage(m)
	assert.Equal(t, ErrCommitHeightMismatch, err)
}

func TestVerifyCommitMessageRound(t *testing.T) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	m, _, privateKey := createCommitMessage(t, 10, 1, state)
	consensus := createConsensus(t, 9, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})

	// set stage
	consensus.currentRound.Stage = stageCommit

	err = consensus.verifyCommitMessage(m)
	assert.Equal(t, ErrCommitRoundMismatch, err)
}

func TestVerifyCommitMessageStateMismatch(t *testing.T) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	m, _, privateKey := createCommitMessage(t, 10, 10, state)
	consensus := createConsensus(t, 9, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})

	// set stage & random locked state
	consensus.currentRound.Stage = stageCommit
	consensus.currentRound.LockedState = make([]byte, 1024)
	_, err = io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	err = consensus.verifyCommitMessage(m)
	assert.Equal(t, ErrCommitStateMismatch, err)
}

func TestVerifyCommitMessageStatusInValid(t *testing.T) {
	state := make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, state)
	assert.Nil(t, err)

	m, _, privateKey := createCommitMessage(t, 10, 10, state)
	consensus := createConsensus(t, 9, 10, []*ecdsa.PublicKey{&privateKey.PublicKey})

	// incorrect stage
	consensus.currentRound.Stage = stageRoundChanging

	err = consensus.verifyCommitMessage(m)
	assert.Equal(t, ErrCommitStatus, err)
}

///////////////////////////////////////////////////////////////////////////////
//
// <decide> message related tests
//
///////////////////////////////////////////////////////////////////////////////
func TestVerifyDecideMessageCorrect(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 9, 10, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Nil(t, err)
}

func TestValidateDecideMessageCorrect(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 9, 10, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)
	bts, err := proto.Marshal(sp)
	assert.Nil(t, err)

	err = consensus.ValidateDecideMessage(bts, m.State)
	assert.Nil(t, err)
}

func TestValidateDecideMessageUnknowParticipant(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 9, 10, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)
	bts, err := proto.Marshal(sp)
	assert.Nil(t, err)

	consensus = createConsensus(t, 9, 10, nil)
	err = consensus.ValidateDecideMessage(bts, m.State)
	assert.NotNil(t, err)
}

func TestVerifyDecideMessageState(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 9, 10, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// set state to nil & resign
	m.State = nil
	sp.Sign(m, privateKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideEmptyState, err)
}

func TestVerifyDecideMessageHeight(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 10, 10, 10, 10)
	consensus := createConsensus(t, 10, 10, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideHeightLower, err)
}

func TestVerifyDecideMessageNotSignedByLeader(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 1, 0, 1, 0)
	_ = privateKey
	consensus := createConsensus(t, 0, 0, proofKeys)

	// set a random leader
	randKey, err := ecdsa.GenerateKey(S256Curve, rand.Reader)
	assert.Nil(t, err)
	consensus.SetLeader(&randKey.PublicKey)

	err = consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideNotSignedByLeader, err)
}

func TestVerifyDecideMessageProofType(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// create a random signed proof with incorrect type
	proof, signedProof, proofKey := createRoundChangeMessageState(t, 1, 0, m.State)
	proof.Type = MessageType_Lock
	// re-sign the proof
	signedProof.Sign(proof, proofKey)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replace with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideProofTypeMismatch, err)
}

func TestVerifyDecideMessageProofHeight(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// create a random signed proof with incorrect height
	_, signedProof, proofKey := createCommitMessage(t, uint64(mrand.Int31n(100000)+100), 0, m.State)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replace with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideProofHeightMismatch, err)
}

func TestVerifyDecideMessageProofRound(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// create a random signed proof with incorrect round
	_, signedProof, proofKey := createCommitMessage(t, 1, uint64(mrand.Int31n(100000)+100), m.State)
	consensus.AddParticipant(&proofKey.PublicKey)

	// random replace with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideProofRoundMismatch, err)
}

func TestVerifyDecideMessageProofUnknownParticipant(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	_, signedProof, _ := createCommitMessage(t, 1, 0, m.State)
	// random replace with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	m.Proof[i] = signedProof
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideProofUnknownParticipant, err)
}

func TestVerifyDecideMessageProofSignature(t *testing.T) {
	m, sp, privateKey, proofKeys := createDecideMessage(t, 20, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)

	consensus.SetLeader(&privateKey.PublicKey)

	// random replace with this incorrect proof
	i := mrand.Int() % len(m.Proof)
	_, _ = io.ReadFull(rand.Reader, m.Proof[i].R)
	_, _ = io.ReadFull(rand.Reader, m.Proof[i].S)
	// re-sign the sp with a incorrectly signed proof
	sp.Sign(m, privateKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrMessageSignature, err)
}

func TestVerifyDecideMessageProofInsufficient(t *testing.T) {
	quorum := 20
	m, sp, privateKey, proofKeys := createDecideMessage(t, quorum, 1, 0, 1, 0)
	consensus := createConsensus(t, 0, 0, proofKeys)
	consensus.SetLeader(&privateKey.PublicKey)

	// random remove a valid proof from the first 2t+1(B)
	valid := 2*((quorum-1)/3) + 1
	i := mrand.Int() % valid
	copy(m.Proof[i:], m.Proof[i+1:])
	m.Proof = m.Proof[:len(m.Proof)-1]
	// re-sign the message
	sp.Sign(m, privateKey)

	err := consensus.verifyDecideMessage(m, sp)
	assert.Equal(t, ErrDecideProofInsufficient, err)
}

func BenchmarkSecp256k1Verify(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(S256Curve, rand.Reader)

	for i := 0; i < b.N; i++ {
		_, sp, _ := createRoundChangeMessageSigner(b, 0, 0, nil, privateKey)
		sp.Verify(S256Curve)
	}
}
