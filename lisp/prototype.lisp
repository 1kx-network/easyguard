(defpackage #:easyguard (:use :cl))
(in-package #:easyguard)

;; Define a global variable to hold the opcode table.
;; An array of size 256 is suitable for indices 0x00 to 0xFF.
;; Initialize with 0, assuming 0 means disallowed or default.
(defparameter *opcode-table* (make-array 256 :element-type 'list :initial-element '(nil nil nil)))
  "Global table mapping EVM opcodes (integer index) to configuration values.
   Initialized by INITIALIZE-OPCODE-TABLE.
   Value format appears inconsistent in original source (comments vs values),
   this table uses the literal hex values from the original code.")

(defun initialize-opcode-table ()
  "Populates the global *opcode-table* with EVM opcode configurations.
   This directly translates the assignments from the provided source code."

  ;; NOTE: The original source code has comments indicating a format like
  ;; (allowed << 4) | (consumed << 2) | produced.
  ;; However, the actual hex values assigned (e.g., #x15 for ADD which comments suggest is 2/1)
  ;; often do not match that encoding based on the comments (e.g., 2/1 would be #x19).
  ;; This translation uses the *literal hex values* present in the original code snippet.

  ;; Re-initialize the array to ensure size and clear previous values
  (setf *opcode-table* (make-array 256 :element-type 'list :initial-element '(nil nil nil)))

  ;; Stop and arithmetic operations
  (setf (aref *opcode-table* #x00) '(t 0 0)) ; STOP
  (setf (aref *opcode-table* #x01) '(t 2 1)) ; ADD
  (setf (aref *opcode-table* #x02) '(t 2 1)) ; MUL
  (setf (aref *opcode-table* #x03) '(t 2 1)) ; SUB
  (setf (aref *opcode-table* #x04) '(t 2 1)) ; DIV
  (setf (aref *opcode-table* #x05) '(t 2 1)) ; SDIV
  (setf (aref *opcode-table* #x06) '(t 2 1)) ; MOD
  (setf (aref *opcode-table* #x07) '(t 2 1)) ; SMOD
  (setf (aref *opcode-table* #x08) '(t 2 1)) ; ADDMOD
  (setf (aref *opcode-table* #x09) '(t 2 1)) ; MULMOD
  (setf (aref *opcode-table* #x0A) '(t 2 1)) ; EXP

  ;; Comparison & bitwise logic operations
  (setf (aref *opcode-table* #x10) '(t 2 1)) ; LT
  (setf (aref *opcode-table* #x11) '(t 2 1)) ; GT
  (setf (aref *opcode-table* #x12) '(t 2 1)) ; SLT
  (setf (aref *opcode-table* #x13) '(t 2 1)) ; SGT
  (setf (aref *opcode-table* #x14) '(t 2 1)) ; EQ
  (setf (aref *opcode-table* #x15) '(t 1 1)) ; ISZERO
  (setf (aref *opcode-table* #x16) '(t 2 1)) ; AND
  (setf (aref *opcode-table* #x17) '(t 2 1)) ; OR
  (setf (aref *opcode-table* #x18) '(t 2 1)) ; XOR
  (setf (aref *opcode-table* #x19) '(t 1 1)) ; NOT

  ;; SHA3
  (setf (aref *opcode-table* #x20) '(t 2 1)) ; SHA3

  ;; Environmental Information
  (setf (aref *opcode-table* #x30) '(t 0 1)) ; ADDRESS
  (setf (aref *opcode-table* #x31) '(t 1 1)) ; BALANCE
  (setf (aref *opcode-table* #x32) '(t 0 1)) ; ORIGIN
  (setf (aref *opcode-table* #x33) '(t 0 1)) ; CALLER
  (setf (aref *opcode-table* #x34) '(t 0 1)) ; CALLVALUE
  (setf (aref *opcode-table* #x35) '(t 1 1)) ; CALLDATALOAD
  (setf (aref *opcode-table* #x36) '(t 0 1)) ; CALLDATASIZE
  (setf (aref *opcode-table* #x37) '(t 3 0)) ; CALLDATACOPY
  (setf (aref *opcode-table* #x38) '(t 0 1)) ; CODESIZE
  (setf (aref *opcode-table* #x39) '(t 3 0)) ; CODECOPY
  (setf (aref *opcode-table* #x3A) '(t 0 1)) ; GASPRICE

  ;; Block Information
  (setf (aref *opcode-table* #x40) '(t 1 1)) ; BLOCKHASH
  (setf (aref *opcode-table* #x41) '(t 0 1)) ; COINBASE
  (setf (aref *opcode-table* #x42) '(t 0 1)) ; TIMESTAMP
  (setf (aref *opcode-table* #x43) '(t 0 1)) ; NUMBER
  (setf (aref *opcode-table* #x44) '(t 0 1)) ; DIFFICULTY/PREVRANDAO
  (setf (aref *opcode-table* #x45) '(t 0 1)) ; GASLIMIT
  (setf (aref *opcode-table* #x46) '(t 0 1)) ; CHAINID
  (setf (aref *opcode-table* #x47) '(t 0 1)) ; SELFBALANCE

  ;; Stack, Memory, Storage and Flow Operations
  (setf (aref *opcode-table* #x50) '(t 1 0)) ; POP
  (setf (aref *opcode-table* #x51) '(t 1 1)) ; MLOAD
  (setf (aref *opcode-table* #x52) '(t 2 0)) ; MSTORE
  (setf (aref *opcode-table* #x53) '(t 2 0)) ; MSTORE8
  (setf (aref *opcode-table* #x54) '(t 1 1)) ; SLOAD
  (setf (aref *opcode-table* #x55) '(t 2 0)) ; SSTORE
  (setf (aref *opcode-table* #x56) '(t 1 0)) ; JUMP
  (setf (aref *opcode-table* #x57) '(t 2 0)) ; JUMPI
  (setf (aref *opcode-table* #x58) '(t 0 1)) ; PC
  (setf (aref *opcode-table* #x59) '(t 0 1)) ; MSIZE
  (setf (aref *opcode-table* #x5A) '(t 0 1)) ; GAS
  (setf (aref *opcode-table* #x5B) '(t 0 0)) ; JUMPDEST
  (setf (aref *opcode-table* #x5E) '(t 3 0)) ; MCOPY

  ;; Push operations (0x5F-0x7F)
  (loop for i from #x5F to #x7F do
    (setf (aref *opcode-table* i) '(t 0 1))) ; PUSH1-PUSH32

  ;; Duplication operations (0x80-0x8F)
  (loop for i from #x80 to #x8F do
    (setf (aref *opcode-table* i) '(t 0 1))) ; DUP1-DUP16

  ;; Exchange operations (0x90-0x9F)
  (loop for i from #x90 to #x9F do
    (setf (aref *opcode-table* i) '(t 1 1))) ; SWAP1-SWAP16

  ;; Logging operations are not allowed (remain 0 by initial element)
  ;; Calls are not allowed (remain 0 by initial element)
  ;; TODO: we may allow STATICCALL to a whitelist of contracts and methods. (Comment retained)

  ;; RETURN is allowed
  (setf (aref *opcode-table* #xF3) '(t 2 0)) ; RETURN
  ;; System operations: REVERT is allowed
  (setf (aref *opcode-table* #xFD) '(t 2 0)) ; REVERT

  ;; Return the populated table (optional, as it modifies the global var)
  *opcode-table*)

;; Call the function once to populate the table
(initialize-opcode-table)

(defparameter *max-stack-size* 64)

(defun swap-stack (stack swap-index)
  "implementation of SWAPx instructions on stack represented as list"
  (cons (nth swap-index stack)
        (append (subseq stack 1 swap-index)
                (list (car stack))
                (nthcdr (+ 1 swap-index) stack))))

(defparameter *visited-limit* 1024 "Max codewalk depth limit")

(defun dfs-walk-code (code pc visited stack)
  (when (> (length visited) 1024) ; Basic cycle/depth limit
        (error "DFS depth or cycle limit exceeded at PC ~X" pc))
  (assert (< pc (length code)) () "PC ~X out of bounds (~A)" pc (length code))
  (assert (not (member pc visited :test #'=)) () "Cycle detected at PC ~X"pc)
  
  (let* ((opcode (aref code pc)))
    (destructuring-bind (allowed consumed produced)
        (aref *opcode-table* opcode)
      (assert allowed () "opcode ~X at PC ~A not allowed" opcode pc)
      (assert (>= (length stack) consumed) () "stack underflow at PC ~A (Opcode ~X): need ~A, have ~A"
              pc opcode consumed (length stack))

      ;; Calculate potential new stack size *before* overflow check.
      (let ((new-stack-size (+ (- (length stack) consumed) produced)))
           (assert (<= new-stack-size *max-stack-size*) () "Stack overflow at PC ~X (Opcode ~X): size would be ~A"
                   pc opcode new-stack-size))

      (let ((next-pc (+ pc 1)) ; Default next PC
            (next-visited (cons pc visited)))
              
        (cond
          ;; -- PUSH --
          ((<= #x5F opcode #x7F)
             (let* ((push-bytes (- opcode #x5F))
                    (value 0))
               ;; Check if push reads past end of code
               (assert (<= (+ pc 1 push-bytes) (length code)) () "PUSH reads past end of code at PC ~X" pc)
                
               (loop for i from 1 to push-bytes
                     do (setf value (logior (ash value 8) (aref code (+ pc i)))))

               (setf next-pc (+ pc 1 push-bytes))
               
               (dfs-walk-code code
                              next-pc
                              next-visited
                              (cons `(:constant ,value) stack))))
          ;; -- JUMP --
          ((= opcode #x56)
           (let ((target-spec (car stack)))
             (assert (and (listp target-spec) (eq (first target-spec) :constant))
                     () "JUMP target is not :constant at PC ~X" pc)
             (let ((target-pc (second target-spec)))
               (assert (integerp target-pc) () "JUMP target PC is not an integer at PC ~X" pc)
               (assert (< target-pc (length code)) () "JUMP target PC ~X out of bounds at PC ~X" target-pc pc)
               (assert (= (aref code target-pc) #x5B) () "JUMP destination ~X is not JUMPDEST (Opcode: ~X)"
                       target-pc (aref code target-pc))
               (dfs-walk-code code target-pc next-visited (cdr stack))))) ; Jump, pop 1
          
          ((= opcode #x57)
           (let ((target-spec (car stack))
                 (condition-spec (cadr stack))) ; Condition is second item popped
              (declare (ignore condition-spec)) ; In static analysis, we explore both paths
              (assert (and (listp target-spec) (eq (first target-spec) :constant))
                      () "JUMPI target is not :constant at PC ~X" pc)
              (let ((target-pc (second target-spec)))
                (assert (integerp target-pc) () "JUMPI target PC is not an integer at PC ~X" pc)
                (assert (< target-pc (length code)) () "JUMPI target PC ~X out of bounds at PC ~X" target-pc pc)
                (assert (= (aref code target-pc) #x5B) () "JUMPI destination ~X is not JUMPDEST (Opcode: ~X)"
                        target-pc (aref code target-pc))
                ;; Explore both paths, pop 2 from stack for both
                (let ((next-stack (cddr stack)))
                    (dfs-walk-code code next-pc next-visited next-stack)     ; Fall-through path
                    (dfs-walk-code code target-pc next-visited next-stack))))) ; Jump path

          ;; --- PC ---
          ((= opcode #x58)
           (dfs-walk-code code next-pc next-visited (cons `(:constant ,pc) stack)))

          ;; --- DUPx ---
          ((<= #x80 opcode #x8F)
           (let ((dup-n (- opcode #x7F))) ; 1 for DUP1, 16 for DUP16
             (assert (>= (length stack) dup-n) () "DUP stack underflow at PC ~X" pc)
             (let ((dup-item (nth (- dup-n 1) stack))) ; Use 0-based index
               (dfs-walk-code code next-pc next-visited (cons dup-item stack)))))


          ;; --- SWAPx ---
          ((<= #x90 opcode #x9F)
           (let ((swap-n (- opcode #x8F))) ; 1 for SWAP1, 16 for SWAP16
             (assert (>= (length stack) (+ swap-n 1)) () "SWAP stack underflow at PC ~X" pc) ; Need N+1 items
             (dfs-walk-code code next-pc next-visited (swap-stack stack swap-n))))
          

          ;; --- Default Case (Arithmetic, Logic, Memory, etc.) ---
          (t
           (let* ((remaining-stack (nthcdr consumed stack))
                  ;; Using :unknown as placeholder, adjust if needed
                  (produced-items (loop repeat produced collect :unknown))
                  (new-stack (append produced-items remaining-stack)))
               ;; Check for STOP, RETURN, REVERT, INVALID etc. to terminate path if needed
               (if (member opcode '(#x00 #xF3 #xFD)) ; STOP, RETURN, REVERT
                   (progn
                      ;; Path finished, maybe return stack state or t
                      (format t "~&Path terminated at PC ~X with Opcode ~X~%" pc opcode)
                      t)
                   ;; Continue walking for other opcodes
                   (dfs-walk-code code next-pc next-visited new-stack)))))))))
