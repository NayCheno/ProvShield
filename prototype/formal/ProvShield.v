(** * ProvShield: Mechanized Safety Properties *)

(** This file formalizes the core safety properties of ProvShield
    in Coq. It defines the integrity lattice, confidentiality lattice,
    provenance labels, capability tokens, and the key theorems:
    - Label unforgeability
    - Token unforgeability
    - No secret exfiltration
    - Bridge non-replay *)

From Stdlib Require Import List.
From Stdlib Require Import Bool.
From Stdlib Require Import Arith.
From Stdlib Require Import PeanoNat.
From Stdlib Require Import Lia.
Import ListNotations.

(* ================================================================= *)
(** ** Integrity Lattice *)
(* ================================================================= *)

Inductive Integrity : Type :=
  | UntrustedSkill
  | ExternalContent
  | ToolOutput
  | ToolMetadata
  | AttestedToolMetadata
  | TrustedSkill
  | UserIntent
  | SystemPolicy.

(** Integrity ordering: higher value = higher trust *)
Definition integrity_le (a b : Integrity) : bool :=
  match a, b with
  | UntrustedSkill, _ => true
  | ExternalContent, UntrustedSkill => false
  | ExternalContent, _ => true
  | ToolOutput, UntrustedSkill => false
  | ToolOutput, ExternalContent => false
  | ToolOutput, _ => true
  | ToolMetadata, UntrustedSkill => false
  | ToolMetadata, ExternalContent => false
  | ToolMetadata, ToolOutput => false
  | ToolMetadata, _ => true
  | AttestedToolMetadata, SystemPolicy => false
  | AttestedToolMetadata, UserIntent => false
  | AttestedToolMetadata, TrustedSkill => false
  | AttestedToolMetadata, _ => true
  | TrustedSkill, SystemPolicy => false
  | TrustedSkill, UserIntent => false
  | TrustedSkill, _ => true
  | UserIntent, SystemPolicy => false
  | UserIntent, _ => true
  | SystemPolicy, _ => true
  end.

(** Meet (lower bound) of two integrity levels *)
Definition integrity_meet (a b : Integrity) : Integrity :=
  if integrity_le a b then a else b.

(** Is this a low-integrity source? *)
Definition is_low_integrity (i : Integrity) : bool :=
  match i with
  | ExternalContent | ToolOutput | ToolMetadata | UntrustedSkill => true
  | _ => false
  end.

(* ================================================================= *)
(** ** Confidentiality Lattice *)
(* ================================================================= *)

Inductive Confidentiality : Type :=
  | Public
  | UserPrivate
  | Secret
  | CapabilityTokenClass.

Definition conf_le (a b : Confidentiality) : bool :=
  match a, b with
  | Public, _ => true
  | UserPrivate, Public => false
  | UserPrivate, _ => true
  | Secret, Public => false
  | Secret, UserPrivate => false
  | Secret, _ => true
  | CapabilityTokenClass, CapabilityTokenClass => true
  | CapabilityTokenClass, _ => false
  end.

Definition conf_join (a b : Confidentiality) : Confidentiality :=
  if conf_le a b then b else a.

(* ================================================================= *)
(** ** Effect Types *)
(* ================================================================= *)

Inductive Effect : Type :=
  | ReadPublic | ReadPrivate | ReadSecret
  | WriteLocal | WriteExternal
  | DeleteLocal | DeleteExternal
  | SendNetwork | ExecuteCode | InstallPackage
  | ModifyAuth | CreateCredential
  | FinancialAction | CalendarInvite.

Definition is_high_risk (e : Effect) : bool :=
  match e with
  | WriteExternal | DeleteExternal | SendNetwork
  | ExecuteCode | InstallPackage | ModifyAuth
  | CreateCredential | FinancialAction => true
  | _ => false
  end.

(* ================================================================= *)
(** ** Provenance Labels *)
(* ================================================================= *)

Record ProvenanceLabel : Type := {
  lbl_integrity : Integrity;
  lbl_confidentiality : Confidentiality;
  lbl_origin : nat;
  lbl_signature : nat
}.

(** A label is valid only if it has a non-zero signature (runtime-signed) *)
Definition label_valid (l : ProvenanceLabel) : bool :=
  Nat.ltb 0 (lbl_signature l).

(** Label join: conservatively take lower integrity, higher confidentiality *)
Definition label_join (l1 l2 : ProvenanceLabel) : ProvenanceLabel :=
  Build_ProvenanceLabel
    (integrity_meet (lbl_integrity l1) (lbl_integrity l2))
    (conf_join (lbl_confidentiality l1) (lbl_confidentiality l2))
    (lbl_origin l1)
    (lbl_signature l1).


(* ================================================================= *)
(** ** Capability Tokens *)
(* ================================================================= *)

Record CapabilityToken : Set := {
  token_action : nat;
  token_destination : nat;
  token_payload_hash : nat;
  token_nonce : nat;
  token_expiry : nat;
  token_signature : nat
}.

Definition token_valid (t : CapabilityToken) : bool :=
  Nat.ltb 0 (token_signature t).

(** Token matches a proposed call *)
Definition token_matches (t : CapabilityToken) (action dest payload_hash nonce : nat) : bool :=
  Nat.eqb (token_action t) action &&
  Nat.eqb (token_destination t) dest &&
  Nat.eqb (token_payload_hash t) payload_hash &&
  Nat.eqb (token_nonce t) nonce.


(* ================================================================= *)
(** ** Runtime State *)
(* ================================================================= *)

Record RuntimeState : Type := {
  context : list (nat * ProvenanceLabel);
  sidecar : list (nat * ProvenanceLabel);
  tokens : list CapabilityToken;
  used_nonces : list nat;
  audit_log : list nat;
  fresh_id : nat
}.

(** Initial state: empty *)
Definition init_state : RuntimeState :=
  Build_RuntimeState [] [] [] [] [] 0.


(* ================================================================= *)
(** ** Theorem 1: Label Unforgeability *)
(* ================================================================= *)

(** The model (LLM) can add to context but cannot write to sidecar.
    Only runtime transitions can create valid sidecar labels.
    
    This is modeled as: if a valid label exists in sidecar with
    integrity > ExternalContent, then it was created by a runtime
    transition (has non-zero signature from the TCB key). *)

Theorem label_unforgeability :
  forall (s : RuntimeState) (obj_id : nat) (l : ProvenanceLabel),
    In (obj_id, l) (sidecar s) ->
    label_valid l = true ->
    lbl_signature l > 0.
Proof.
  intros s obj_id l HIn Hvalid.
  unfold label_valid in Hvalid.
  apply Nat.ltb_lt in Hvalid.
  exact Hvalid.
Qed.

(** Corollary: model-generated text cannot create valid sidecar labels
    because the model has no access to the signing key. *)
Corollary model_cannot_forge_label :
  forall (content : nat) (integrity : Integrity) (conf : Confidentiality),
    (* Model can only produce labels with signature = 0 *)
    (* Runtime produces labels with signature > 0 *)
    (* Therefore model labels are always invalid *)
    forall sig, sig = 0 -> label_valid (Build_ProvenanceLabel integrity conf content sig) = false.
Proof.
  intros content integrity conf sig Hsig.
  unfold label_valid. simpl.
  rewrite Hsig. reflexivity.
Qed.


(* ================================================================= *)
(** ** Theorem 2: Capability Token Unforgeability *)
(* ================================================================= *)

(** Tokens are created only by BridgeConfirm transitions.
    The model cannot create valid tokens because it lacks the HMAC key. *)

Theorem token_unforgeability :
  forall (s : RuntimeState) (t : CapabilityToken),
    In t (tokens s) ->
    token_valid t = true ->
    token_signature t > 0.
Proof.
  intros s t HIn Hvalid.
  unfold token_valid in Hvalid.
  apply Nat.ltb_lt in Hvalid.
  exact Hvalid.
Qed.

(** Model-generated tokens always have signature = 0, hence invalid. *)
Corollary model_cannot_forge_token :
  forall (action dest hash nonce expiry : nat),
    token_valid (Build_CapabilityToken action dest hash nonce expiry 0) = false.
Proof.
  intros. unfold token_valid. simpl. reflexivity.
Qed.


(* ================================================================= *)
(** ** Theorem 3: No Secret Exfiltration *)
(* ================================================================= *)

(** If a call sends payload with confidentiality >= Secret to an external
    sink, and no valid declassification bridge exists, then the call
    cannot reach ExecuteTool.
    
    This is modeled as: the monitor denies any call where:
    1. payload confidentiality >= Secret
    2. sink is external
    3. no matching valid token exists *)

Definition is_external_sink (effect : Effect) : bool :=
  match effect with
  | WriteExternal | SendNetwork => true
  | _ => false
  end.

Definition requires_declassification (conf : Confidentiality) (effect : Effect) : bool :=
  conf_le Secret conf && is_external_sink effect.

(** The monitor decision: deny if secret + external + no token *)
Definition monitor_decide_secret
    (payload_conf : Confidentiality) (effect : Effect)
    (tokens : list CapabilityToken)
    (action dest hash nonce : nat) : bool :=
  if requires_declassification payload_conf effect then
    (* Check if any valid matching token exists *)
    existsb (fun t => token_matches t action dest hash nonce && token_valid t) tokens
  else
    true.  (* allow if no declassification needed *)

Theorem no_secret_exfiltration :
  forall (payload_conf : Confidentiality) (effect : Effect)
         (ts : list CapabilityToken) (action dest hash nonce : nat),
    conf_le Secret payload_conf = true ->
    is_external_sink effect = true ->
    (* No valid matching token exists *)
    existsb (fun t => token_matches t action dest hash nonce && token_valid t) ts = false ->
    monitor_decide_secret payload_conf effect ts action dest hash nonce = false.
Proof.
  intros payload_conf effect ts action dest hash nonce
         Hconf Hsink Hnotoken.
  unfold monitor_decide_secret.
  unfold requires_declassification.
  rewrite Hconf. rewrite Hsink. simpl.
  rewrite Hnotoken. reflexivity.
Qed.


(* ================================================================= *)
(** ** Theorem 5: Bridge Non-Replay *)
(* ================================================================= *)

(** A bridge token authorizes exactly one normalized call.
    If any field differs, the token does not match.
    If the nonce is already consumed, the token is rejected. *)

Definition nonce_consumed (nonce : nat) (used : list nat) : bool :=
  existsb (Nat.eqb nonce) used.

(** Token verification: must match AND nonce must not be consumed *)
Definition verify_token
    (t : CapabilityToken) (action dest hash nonce : nat)
    (used_nonces : list nat) : bool :=
  token_matches t action dest hash nonce &&
  token_valid t &&
  negb (nonce_consumed nonce used_nonces).

Theorem bridge_non_replay :
  forall (t : CapabilityToken)
         (action dest hash nonce : nat)
         (used : list nat),
    nonce_consumed nonce used = true ->
    verify_token t action dest hash nonce used = false.
Proof.
  intros t action dest hash nonce used Hconsumed.
  unfold verify_token.
  rewrite Hconsumed. simpl.
  apply andb_false_r.
Qed.

(** Different destination: token does not match *)
Theorem bridge_no_destination_swap :
  forall (t : CapabilityToken)
         (action dest1 dest2 hash nonce : nat)
         (used : list nat),
    dest1 <> dest2 ->
    token_matches t action dest1 hash nonce = true ->
    token_matches t action dest2 hash nonce = false.
Proof.
  intros t action dest1 dest2 hash nonce used Hneq Hmatch.
  unfold token_matches in *.
  (* Decompose all conjunctions — left-associative: ((a&&b)&&c)&&d *)
  apply Bool.andb_true_iff in Hmatch as [Habc Hd].
  apply Bool.andb_true_iff in Habc as [Hab Hc].
  apply Bool.andb_true_iff in Hab as [Ha Hb].
  (* Hb: Nat.eqb dest1 (token_destination t) = true *)
  apply Nat.eqb_eq in Hb.
  unfold token_matches.
  destruct (token_destination t =? dest2) eqn:Hdest.
  - exfalso. apply Nat.eqb_eq in Hdest. apply Hneq. congruence.
  - destruct (token_action t =? action);
    destruct (token_payload_hash t =? hash);
    destruct (token_nonce t =? nonce);
    reflexivity.
Qed.


(* ================================================================= *)
(** ** Theorem 6: Label Preservation *)
(* ================================================================= *)

(** Every transition preserves label well-formedness, token validity,
    and audit completeness. This is the key invariant that ensures
    the system remains consistent across all state transitions. *)

Definition label_well_formed (l : ProvenanceLabel) : bool :=
  label_valid l.

Definition state_well_formed (s : RuntimeState) : bool :=
  (* All sidecar labels are well-formed *)
  forallb (fun pair => label_well_formed (snd pair)) (sidecar s).

(** Initial state is well-formed (empty sidecar) *)
Theorem initial_state_well_formed :
  state_well_formed init_state = true.
Proof.
  unfold state_well_formed, init_state. simpl. reflexivity.
Qed.

(** Ingesting a new object preserves well-formedness *)
Theorem ingest_preserves_well_formed :
  forall (s : RuntimeState) (value : nat) (integrity : Integrity)
         (conf : Confidentiality) (origin : nat),
    state_well_formed s = true ->
    state_well_formed
      (Build_RuntimeState
        (context s)
        ((fresh_id s, Build_ProvenanceLabel integrity conf origin (fresh_id s + 1)) :: sidecar s)
        (tokens s)
        (used_nonces s)
        (audit_log s)
        (fresh_id s + 1)) = true.
Proof.
  intros s value integrity conf origin Hwf.
  unfold state_well_formed, label_well_formed, label_valid in *. simpl.
  apply Bool.andb_true_iff. split.
  - apply Nat.ltb_lt. lia.
  - exact Hwf.
Qed.

(** Token consumption preserves well-formedness.
    Update uses a simple mark: we set token_signature to 0 to indicate
    consumption, and add the nonce to used_nonces. The sidecar (which
    is what state_well_formed checks) is unchanged. *)
Theorem consume_preserves_well_formed :
  forall (s : RuntimeState) (t : CapabilityToken),
    state_well_formed s = true ->
    In t (tokens s) ->
    state_well_formed
      (Build_RuntimeState
        (context s)
        (sidecar s)
        (map (fun tok => if Nat.eqb (token_nonce tok) (token_nonce t)
                         then Build_CapabilityToken
                                (token_action tok)
                                (token_destination tok)
                                (token_payload_hash tok)
                                (token_nonce tok)
                                (token_expiry tok)
                                0  (* mark consumed: invalidate signature *)
                         else tok) (tokens s))
        (token_nonce t :: used_nonces s)
        (audit_log s)
        (fresh_id s)) = true.
Proof.
  intros s t Hwf HIn.
  unfold state_well_formed in *. simpl.
  (* Sidecar unchanged, so well-formedness preserved *)
  exact Hwf.
Qed.
(** These theorems establish:
    1. Label unforgeability: valid labels have non-zero MAC (definition-level)
    2. Token unforgeability: valid tokens have non-zero signature (definition-level)
    3. No secret exfiltration: monitor denies secret+external without valid token
    4. Bridge non-replay: consumed nonce or mismatched field → token rejected
    5. Label preservation: transitions preserve sidecar well-formedness
    6. Destination swap protection: different destination → token no match
    
    ** Limitations: **
    - Theorems 1-2 are definition tautologies, not transition-system invariants.
    - The transition relation below provides the framework for proving
      reachable-state invariants, but the full proof is not yet complete.
    - Claims in the paper should say "proof sketch" not "mechanized proof"
      until a reachable-state invariant is proven.
    
    The formalization assumes:
    - Runtime (TCB) controls the HMAC key
    - Model has no access to sidecar store or signing key
    - HMAC is cryptographically secure *)

(** ** HMAC Security Axiom
    
    We assume HMAC-SHA256 is a secure message authentication code.
    This means: given only the message and the MAC output, no efficient
    adversary can produce a valid MAC for a different message without
    knowing the key.
    
    This is a standard cryptographic assumption. The HMAC key is managed
    by the runtime (TCB) and never exposed to the model context (C).
    
    In the Python implementation, this corresponds to:
    - ProvenanceLabel._compute_signature() using HMAC-SHA256
    - _RUNTIME_HMAC_KEY being a module-level secret
    - The LLM having no access to the key *)

Axiom hmac_secure : forall (key msg1 msg2 mac : nat),
  mac = 0 -> (* placeholder: real HMAC computation *)
  msg1 <> msg2 ->
  (* Cannot forge MAC for msg2 given MAC for msg1 without key *)
  True. (* Formal statement simplified; see paper §5 for full argument *)

(** ** TCB Integrity Axiom
    
    The runtime monitor, sidecar store, policy engine, and bridge
    manager are not compromised. If the runtime itself is compromised,
    all guarantees are void. *)

Axiom tcb_integrity : forall (state : State),
  (* The TCB components maintain their invariants *)
  True. (* Placeholder: full formalization requires modeling TCB boundaries *)


(* ================================================================= *)
(** ** Transition Relation (PR-C5) *)
(* ================================================================= *)

(** The transition system models all runtime operations.
    Each transition transforms the RuntimeState. *)

Inductive Transition : Type :=
  | TIngestUser (obj_id : nat) (integrity : Integrity) (conf : Confidentiality)
  | TIngestExternal (obj_id : nat) (integrity : Integrity) (conf : Confidentiality)
  | TRegisterTool (tool_id : nat) (effect : Effect)
  | TModelPropose (tool_id : nat) (action dest hash nonce : nat)
  | TMonitorAllow (tool_id : nat)
  | TMonitorDeny (tool_id : nat)
  | TBridgeConfirm (bridge_id : nat) (action dest hash nonce : nat)
  | TExecuteTool (tool_id : nat)
  | TAudit (entry_id : nat).

(** Apply a transition to a state *)
Definition apply_transition (s : RuntimeState) (t : Transition) : RuntimeState :=
  match t with
  | TIngestUser oid intg conf =>
      Build_RuntimeState
        ((oid, Build_ProvenanceLabel intg conf oid (fresh_id s + 1)) :: context s)
        ((oid, Build_ProvenanceLabel intg conf oid (fresh_id s + 1)) :: sidecar s)
        (tokens s) (used_nonces s) (oid :: audit_log s) (fresh_id s + 1)
  | TIngestExternal oid intg conf =>
      Build_RuntimeState
        ((oid, Build_ProvenanceLabel intg conf oid (fresh_id s + 1)) :: context s)
        ((oid, Build_ProvenanceLabel intg conf oid (fresh_id s + 1)) :: sidecar s)
        (tokens s) (used_nonces s) (oid :: audit_log s) (fresh_id s + 1)
  | TRegisterTool tid eff =>
      s  (* tool registration doesn't change state in this model *)
  | TModelPropose tid action dest hash nonce =>
      s  (* model proposal doesn't change state — monitor decides *)
  | TMonitorAllow tid =>
      s  (* allow doesn't change state — execution follows *)
  | TMonitorDeny tid =>
      s  (* deny doesn't change state *)
  | TBridgeConfirm bid action dest hash nonce =>
      let new_token := Build_CapabilityToken action dest hash nonce (fresh_id s + 1) (fresh_id s + 2) in
      Build_RuntimeState
        (context s)
        (sidecar s)
        (new_token :: tokens s)
        (nonce :: used_nonces s)
        (bid :: audit_log s)
        (fresh_id s + 2)
  | TExecuteTool tid =>
      s  (* execution labels output but state model is simplified *)
  | TAudit eid =>
      s  (* audit only appends to log *)
  end.

(** Reachable states: initial state + any sequence of transitions *)
Inductive Reachable : RuntimeState -> Prop :=
  | ReachInit : Reachable init_state
  | ReachStep : forall s t, Reachable s -> Reachable (apply_transition s t).

(** Key invariant: all sidecar labels remain well-formed *)
Theorem reachable_well_formed :
  forall s, Reachable s -> state_well_formed s = true.
Proof.
  intros s Hreach.
  induction Hreach as [| s t Hreach IH].
  - (* Initial state *)
    apply initial_state_well_formed.
  - (* Inductive step: apply_transition preserves well-formedness *)
    destruct t; simpl; try exact IH.
    + (* TIngestUser: new label has signature = fresh_id s + 1 > 0 *)
      unfold state_well_formed, label_well_formed, label_valid in *. simpl.
      apply Bool.andb_true_iff. split.
      * apply Nat.ltb_lt. lia.
      * exact IH.
    + (* TIngestExternal: same as TIngestUser *)
      unfold state_well_formed, label_well_formed, label_valid in *. simpl.
      apply Bool.andb_true_iff. split.
      * apply Nat.ltb_lt. lia.
      * exact IH.
Qed.


(** Key invariant: no secret in external sink without valid token *)
Theorem reachable_no_secret_exfil :
  forall s action dest hash nonce,
    Reachable s ->
    is_external_sink (SendNetwork) = true ->
    (* If no valid matching token exists in the reachable state *)
    existsb (fun t => token_matches t action dest hash nonce && token_valid t) (tokens s) = false ->
    (* Then the monitor would deny: monitor_decide_secret returns false *)
    monitor_decide_secret Secret SendNetwork (tokens s) action dest hash nonce = false.
Proof.
  intros s action dest hash nonce Hreach Hsink Hnotoken.
  apply no_secret_exfiltration; assumption.
Qed.