;; Infinity System - Privacy-Preserving Reputation Network
;; Clarity Version: 2
;; Epoch: 2.1
;;
;; Overview:
;; A decentralized reputation network enabling users to build verifiable trust scores
;; across platforms while maintaining anonymity. Uses stake-to-vouch consensus,
;; temporal decay, and anti-gaming measures.

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INSUFFICIENT-STAKE (err u103))
(define-constant ERR-INVALID-SCORE (err u104))
(define-constant ERR-SELF-VOUCH (err u105))
(define-constant ERR-ALREADY-VOUCHED (err u106))
(define-constant ERR-CLAIM-NOT-FOUND (err u107))
(define-constant ERR-INVALID-DECAY (err u108))
(define-constant ERR-SUSPENDED (err u109))

;; Reputation score bounds (0 - 1000)
(define-constant MAX-SCORE u1000)
(define-constant MIN-STAKE u1000000) ;; 1 STX in micro-STX
(define-constant DECAY-INTERVAL u144) ;; ~1 day in blocks
(define-constant DECAY-RATE u2)       ;; 0.2% decay per interval (scaled by 1000)
(define-constant MAX-VOUCHES-PER-USER u50)
(define-constant VOUCH-WEIGHT u10)    ;; score points per vouch
(define-constant GAMING-THRESHOLD u5) ;; max rapid vouches before flag

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Anonymized user profile using hashed identity
(define-map user-profiles
  { identity-hash: (buff 32) }
  {
    reputation-score: uint,
    stake-amount: uint,
    vouch-count: uint,
    last-activity-block: uint,
    is-suspended: bool,
    registered-at: uint,
    platform-count: uint
  }
)

;; Reputation claims (zk-proof placeholder stored as hash)
(define-map reputation-claims
  { claim-id: (buff 32) }
  {
    claimant-hash: (buff 32),
    platform-hash: (buff 32),   ;; hashed platform identifier
    proof-hash: (buff 32),      ;; zk-proof commitment
    score-contribution: uint,
    verified: bool,
    submitted-at: uint,
    expires-at: uint
  }
)

;; Vouch records linking voucher to recipient
(define-map vouch-records
  { voucher-hash: (buff 32), recipient-hash: (buff 32) }
  {
    stake-committed: uint,
    vouched-at: uint,
    is-active: bool
  }
)

;; Anti-gaming: track rapid vouch activity
(define-map vouch-activity-tracker
  { identity-hash: (buff 32) }
  {
    recent-vouch-count: uint,
    window-start-block: uint
  }
)

;; Credential issuance for cross-platform portability
(define-map portable-credentials
  { credential-id: (buff 32) }
  {
    owner-hash: (buff 32),
    score-snapshot: uint,
    issued-at: uint,
    valid-until: uint,
    revoked: bool
  }
)

;; Global stats
(define-data-var total-users uint u0)
(define-data-var total-claims uint u0)
(define-data-var total-vouches uint u0)
(define-data-var protocol-stake-pool uint u0)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

;; Check if a user profile exists
(define-private (profile-exists? (identity-hash (buff 32)))
  (is-some (map-get? user-profiles { identity-hash: identity-hash }))
)

;; Apply temporal decay to a score based on blocks elapsed
(define-private (apply-decay (score uint) (last-block uint))
  (let (
    (blocks-elapsed (- block-height last-block))
    (intervals (/ blocks-elapsed DECAY-INTERVAL))
    (decay-amount (* intervals DECAY-RATE))
    (scaled-decay (/ (* score decay-amount) u1000))
  )
    (if (> scaled-decay score)
      u0
      (- score scaled-decay)
    )
  )
)

;; Detect potential gaming: too many vouches in short window
(define-private (is-gaming? (identity-hash (buff 32)))
  (match (map-get? vouch-activity-tracker { identity-hash: identity-hash })
    tracker
      (and
        (< (- block-height (get window-start-block tracker)) DECAY-INTERVAL)
        (>= (get recent-vouch-count tracker) GAMING-THRESHOLD)
      )
    false
  )
)

;; Cap a score at MAX-SCORE (replaces missing built-in min)
(define-private (cap-score (score uint))
  (if (> score MAX-SCORE) MAX-SCORE score)
)

;; Update vouch activity tracker for anti-gaming
(define-private (update-vouch-tracker (identity-hash (buff 32)))
  (match (map-get? vouch-activity-tracker { identity-hash: identity-hash })
    tracker
      (if (< (- block-height (get window-start-block tracker)) DECAY-INTERVAL)
        (map-set vouch-activity-tracker
          { identity-hash: identity-hash }
          (merge tracker { recent-vouch-count: (+ (get recent-vouch-count tracker) u1) })
        )
        (map-set vouch-activity-tracker
          { identity-hash: identity-hash }
          { recent-vouch-count: u1, window-start-block: block-height }
        )
      )
    (map-set vouch-activity-tracker
      { identity-hash: identity-hash }
      { recent-vouch-count: u1, window-start-block: block-height }
    )
  )
)

;; ============================================================
;; PUBLIC FUNCTIONS
;; ============================================================

;; Register a new anonymous identity
;; identity-hash: keccak/sha256 hash of the user's private identity
(define-public (register-identity (identity-hash (buff 32)))
  (begin
    (asserts! (not (profile-exists? identity-hash)) ERR-ALREADY-REGISTERED)
    (map-set user-profiles
      { identity-hash: identity-hash }
      {
        reputation-score: u0,
        stake-amount: u0,
        vouch-count: u0,
        last-activity-block: block-height,
        is-suspended: false,
        registered-at: block-height,
        platform-count: u0
      }
    )
    (var-set total-users (+ (var-get total-users) u1))
    (ok true)
  )
)

;; Stake STX tokens to participate in reputation system
(define-public (stake-tokens (identity-hash (buff 32)) (amount uint))
  (let (
    (profile (unwrap! (map-get? user-profiles { identity-hash: identity-hash }) ERR-NOT-REGISTERED))
  )
    (asserts! (not (get is-suspended profile)) ERR-SUSPENDED)
    (asserts! (>= amount MIN-STAKE) ERR-INSUFFICIENT-STAKE)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set user-profiles
      { identity-hash: identity-hash }
      (merge profile {
        stake-amount: (+ (get stake-amount profile) amount),
        last-activity-block: block-height
      })
    )
    (var-set protocol-stake-pool (+ (var-get protocol-stake-pool) amount))
    (ok true)
  )
)

;; Submit a reputation claim with zk-proof commitment
;; proof-hash: commitment to zk-SNARK proof generated off-chain
(define-public (submit-reputation-claim
    (claim-id (buff 32))
    (claimant-hash (buff 32))
    (platform-hash (buff 32))
    (proof-hash (buff 32))
    (score-contribution uint)
    (duration-blocks uint))
  (let (
    (profile (unwrap! (map-get? user-profiles { identity-hash: claimant-hash }) ERR-NOT-REGISTERED))
  )
    (asserts! (not (get is-suspended profile)) ERR-SUSPENDED)
    (asserts! (<= score-contribution MAX-SCORE) ERR-INVALID-SCORE)
    (asserts! (is-none (map-get? reputation-claims { claim-id: claim-id })) ERR-ALREADY-REGISTERED)
    (map-set reputation-claims
      { claim-id: claim-id }
      {
        claimant-hash: claimant-hash,
        platform-hash: platform-hash,
        proof-hash: proof-hash,
        score-contribution: score-contribution,
        verified: false,
        submitted-at: block-height,
        expires-at: (+ block-height duration-blocks)
      }
    )
    (var-set total-claims (+ (var-get total-claims) u1))
    (ok true)
  )
)

;; Verify a reputation claim (called by authorized verifier or contract owner)
(define-public (verify-claim (claim-id (buff 32)))
  (let (
    (claim (unwrap! (map-get? reputation-claims { claim-id: claim-id }) ERR-CLAIM-NOT-FOUND))
    (profile (unwrap! (map-get? user-profiles { identity-hash: (get claimant-hash claim) }) ERR-NOT-REGISTERED))
    (decayed-score (apply-decay (get reputation-score profile) (get last-activity-block profile)))
    (new-score (cap-score (+ decayed-score (get score-contribution claim))))
  )
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (not (get verified claim)) ERR-ALREADY-REGISTERED)
    (asserts! (<= block-height (get expires-at claim)) ERR-INVALID-DECAY)
    (map-set reputation-claims
      { claim-id: claim-id }
      (merge claim { verified: true })
    )
    (map-set user-profiles
      { identity-hash: (get claimant-hash claim) }
      (merge profile {
        reputation-score: new-score,
        last-activity-block: block-height,
        platform-count: (+ (get platform-count profile) u1)
      })
    )
    (ok new-score)
  )
)

;; Vouch for another user, committing stake to back the endorsement
(define-public (vouch-for-user
    (voucher-hash (buff 32))
    (recipient-hash (buff 32))
    (stake-amount uint))
  (let (
    (voucher (unwrap! (map-get? user-profiles { identity-hash: voucher-hash }) ERR-NOT-REGISTERED))
    (recipient (unwrap! (map-get? user-profiles { identity-hash: recipient-hash }) ERR-NOT-REGISTERED))
  )
    (asserts! (not (is-eq voucher-hash recipient-hash)) ERR-SELF-VOUCH)
    (asserts! (not (get is-suspended voucher)) ERR-SUSPENDED)
    (asserts! (>= (get stake-amount voucher) stake-amount) ERR-INSUFFICIENT-STAKE)
    (asserts! (>= stake-amount MIN-STAKE) ERR-INSUFFICIENT-STAKE)
    (asserts! (is-none (map-get? vouch-records { voucher-hash: voucher-hash, recipient-hash: recipient-hash })) ERR-ALREADY-VOUCHED)
    (asserts! (not (is-gaming? voucher-hash)) ERR-NOT-AUTHORIZED)
    (let (
      (decayed-score (apply-decay (get reputation-score recipient) (get last-activity-block recipient)))
      (new-score (cap-score (+ decayed-score VOUCH-WEIGHT)))
    )
      (map-set vouch-records
        { voucher-hash: voucher-hash, recipient-hash: recipient-hash }
        {
          stake-committed: stake-amount,
          vouched-at: block-height,
          is-active: true
        }
      )
      (map-set user-profiles
        { identity-hash: recipient-hash }
        (merge recipient {
          reputation-score: new-score,
          vouch-count: (+ (get vouch-count recipient) u1),
          last-activity-block: block-height
        })
      )
      (update-vouch-tracker voucher-hash)
      (var-set total-vouches (+ (var-get total-vouches) u1))
      (ok new-score)
    )
  )
)

;; Issue a portable credential snapshot for cross-platform use
(define-public (issue-credential
    (credential-id (buff 32))
    (owner-hash (buff 32))
    (validity-blocks uint))
  (let (
    (profile (unwrap! (map-get? user-profiles { identity-hash: owner-hash }) ERR-NOT-REGISTERED))
    (current-score (apply-decay (get reputation-score profile) (get last-activity-block profile)))
  )
    (asserts! (not (get is-suspended profile)) ERR-SUSPENDED)
    (asserts! (is-none (map-get? portable-credentials { credential-id: credential-id })) ERR-ALREADY-REGISTERED)
    (map-set portable-credentials
      { credential-id: credential-id }
      {
        owner-hash: owner-hash,
        score-snapshot: current-score,
        issued-at: block-height,
        valid-until: (+ block-height validity-blocks),
        revoked: false
      }
    )
    (ok current-score)
  )
)

;; Revoke a portable credential
(define-public (revoke-credential (credential-id (buff 32)) (owner-hash (buff 32)))
  (let (
    (cred (unwrap! (map-get? portable-credentials { credential-id: credential-id }) ERR-CLAIM-NOT-FOUND))
  )
    (asserts! (is-eq (get owner-hash cred) owner-hash) ERR-NOT-AUTHORIZED)
    (map-set portable-credentials
      { credential-id: credential-id }
      (merge cred { revoked: true })
    )
    (ok true)
  )
)

;; Suspend a user identity (admin only, for confirmed abuse)
(define-public (suspend-identity (identity-hash (buff 32)))
  (let (
    (profile (unwrap! (map-get? user-profiles { identity-hash: identity-hash }) ERR-NOT-REGISTERED))
  )
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set user-profiles
      { identity-hash: identity-hash }
      (merge profile { is-suspended: true })
    )
    (ok true)
  )
)

;; Withdraw staked tokens (reduces stake pool participation)
(define-public (withdraw-stake (identity-hash (buff 32)) (amount uint))
  (let (
    (profile (unwrap! (map-get? user-profiles { identity-hash: identity-hash }) ERR-NOT-REGISTERED))
  )
    (asserts! (>= (get stake-amount profile) amount) ERR-INSUFFICIENT-STAKE)
    (try! (as-contract (stx-transfer? amount tx-sender tx-sender)))
    (map-set user-profiles
      { identity-hash: identity-hash }
      (merge profile {
        stake-amount: (- (get stake-amount profile) amount)
      })
    )
    (var-set protocol-stake-pool (- (var-get protocol-stake-pool) amount))
    (ok true)
  )
)

;; ============================================================
;; READ-ONLY FUNCTIONS
;; ============================================================

;; Get reputation score with live decay applied
(define-read-only (get-reputation-score (identity-hash (buff 32)))
  (match (map-get? user-profiles { identity-hash: identity-hash })
    profile
      (ok (apply-decay (get reputation-score profile) (get last-activity-block profile)))
    ERR-NOT-REGISTERED
  )
)

;; Get full user profile
(define-read-only (get-profile (identity-hash (buff 32)))
  (match (map-get? user-profiles { identity-hash: identity-hash })
    profile (ok profile)
    ERR-NOT-REGISTERED
  )
)

;; Get a reputation claim
(define-read-only (get-claim (claim-id (buff 32)))
  (match (map-get? reputation-claims { claim-id: claim-id })
    claim (ok claim)
    ERR-CLAIM-NOT-FOUND
  )
)

;; Verify a portable credential is valid
(define-read-only (verify-credential (credential-id (buff 32)))
  (match (map-get? portable-credentials { credential-id: credential-id })
    cred
      (ok {
        valid: (and
          (not (get revoked cred))
          (<= block-height (get valid-until cred))
        ),
        score-snapshot: (get score-snapshot cred),
        issued-at: (get issued-at cred),
        valid-until: (get valid-until cred)
      })
    ERR-CLAIM-NOT-FOUND
  )
)

;; Check if a vouch exists between two identities
(define-read-only (check-vouch (voucher-hash (buff 32)) (recipient-hash (buff 32)))
  (match (map-get? vouch-records { voucher-hash: voucher-hash, recipient-hash: recipient-hash })
    record (ok record)
    ERR-CLAIM-NOT-FOUND
  )
)

;; Get global protocol statistics
(define-read-only (get-protocol-stats)
  (ok {
    total-users: (var-get total-users),
    total-claims: (var-get total-claims),
    total-vouches: (var-get total-vouches),
    protocol-stake-pool: (var-get protocol-stake-pool)
  })
)
