(defpackage #:easyguard
  (:use #:cl)
  (:export #:initialize-opcode-table
           #:iterative-dfs-walk-code
           #:*opcode-table*
           #:*max-stack-size*))

(in-package #:easyguard)

;; Opcode table definition and initialization (assuming it's loaded)
(defparameter *opcode-table* nil "Opcode table, initialized by initialize-opcode-table.")
(defparameter *max-stack-size* 1024 "Maximum allowed EVM stack depth.") ; Adjusted from 64

;; Placeholder for initialize-opcode-table - ensure this is defined and called
;; before running the walker. For brevity, its definition is omitted here,
;; but it should populate *opcode-table* as in the previous examples.
(defun initialize-opcode-table ()
  (setf *opcode-table* (make-array 256 :element-type 'list :initial-element '(nil nil nil)))
  ;; ... (rest of the initialization code from previous example) ...
  (setf (aref *opcode-table* #x00) '(t 0 0)) ; STOP
  (setf (aref *opcode-table* #x01) '(t 2 1)) ; ADD
  (setf (aref *opcode-table* #x56) '(t 1 0)) ; JUMP
  (setf (aref *opcode-table* #x57) '(t 2 0)) ; JUMPI
  (setf (aref *opcode-table* #x5B) '(t 0 0)) ; JUMPDEST
  (setf (aref *opcode-table* #x60) '(t 0 1)) ; PUSH1
  (setf (aref *opcode-table* #x80) '(t 1 2)) ; DUP1 - Corrected produced value
  (setf (aref *opcode-table* #x90) '(t 2 2)) ; SWAP1 - Corrected consumed/produced
  (setf (aref *opcode-table* #xF3) '(t 2 0)) ; RETURN
  (setf (aref *opcode-table* #xFD) '(t 2 0)) ; REVERT
  ;; ... Add all other opcodes as needed ...
  *opcode-table*)

;; Placeholder for swap-stack - ensure this is defined if SWAP is used.
(defun swap-stack (stack swap-index)
  "Implementation of SWAPx instructions (inefficient list version)."
  (when (< (length stack) (+ swap-index 1))
    (error "Stack underflow during SWAP~A" swap-index))
  (let ((top (car stack))
        (nth-item (nth swap-index stack)))
    ;; Build the new list carefully
    (cons nth-item ; Nth item goes to top
          (loop for i from 1 below swap-index
                collect (nth i stack) ; Items between top and Nth
          into middle
          finally (return (append middle
                                  (list top) ; Original top goes to Nth position
                                  (nthcdr (+ swap-index 1) stack) ; Rest of the stack
                                  ))))))


(defun iterative-dfs-walk-code (code initial-pc &key (max-depth 1024))
  "Performs an iterative Depth-First Search walk of EVM bytecode.

  Args:
    code: A vector representing the EVM bytecode.
    initial-pc: The starting program counter (usually 0).
    max-depth: Maximum path length to explore (prevents infinite loops in some cycles).

  Returns:
    T if exploration completes, or signals an error.
    (Further enhancements could return collected states or findings).
  "
  (unless *opcode-table*
    (error "*opcode-table* is not initialized. Call initialize-opcode-table first."))

  ;; The control stack holds states to visit: (list pc evm-stack visited-path)
  (let ((control-stack (list (list initial-pc '() '()))))

    (loop while control-stack do
      (let ((current-state (pop control-stack)))
        (destructuring-bind (pc stack visited) current-state

          ;; --- Pre-processing Checks ---
          (when (or (< pc 0) (>= pc (length code)))
            (warn "PC ~X out of bounds (~A), pruning path." pc (length code))
            (continue)) ; Skip this state

          (when (> (length visited) max-depth)
            (warn "Max depth (~A) exceeded at PC ~X, pruning path." max-depth pc)
            (continue))

          (when (member pc visited :test #'=)
            ;; Cycle detected on the current path
            (warn "Cycle detected at PC ~X, pruning path." pc)
            (continue))

          ;; --- Get Opcode and Info ---
          (let* ((opcode (aref code pc))
                 (op-info (aref *opcode-table* opcode)))

            ;; Use handler-case to catch errors for a specific path without stopping the whole walk
            (handler-case
                (destructuring-bind (allowed consumed produced) op-info
                  ;; --- Assertions / State Validity Checks ---
                  (unless allowed
                    (error "Opcode ~X at PC ~X is not allowed." opcode pc)) ; Use error to stop if disallowed opcode encountered

                  (unless (>= (length stack) consumed)
                    (error "Stack underflow at PC ~X (Opcode ~X): need ~A, have ~A."
                           pc opcode consumed (length stack)))

                  (let ((new-stack-size (+ (- (length stack) consumed) produced)))
                    (unless (<= new-stack-size *max-stack-size*)
                      (error "Stack overflow at PC ~X (Opcode ~X): size would be ~A."
                             pc opcode new-stack-size)))

                  ;; --- Calculate Next State(s) based on Opcode ---
                  (let ((next-visited (cons pc visited)))
                    (cond
                      ;; --- Terminating Opcodes ---
                      ((member opcode '(#x00 #xF3 #xFD #xFE)) ; STOP, RETURN, REVERT, INVALID
                       (format t "~&Path terminated at PC ~X with Opcode ~X~%" pc opcode)
                       ;; Don't push anything, just let the loop continue with other states
                       )

                      ;; --- PUSHx ---
                      ((<= #x60 opcode #x7F)
                       (let* ((push-bytes (- opcode #x5F)) ; 1 for PUSH1, 32 for PUSH32
                              (next-pc (+ pc 1 push-bytes))
                              (value 0))
                         (unless (<= next-pc (length code)) ; Check push read boundary
                           (error "PUSH read past end of code at PC ~X." pc))
                         ;; Read the bytes
                         (loop for i from 1 to push-bytes
                               do (setf value (logior (ash value 8) (aref code (+ pc i)))))
                         ;; Push the next state
                         (let ((new-stack (cons `(:constant ,value) stack)))
                           (push (list next-pc new-stack next-visited) control-stack))))

                      ;; --- JUMP ---
                      ((= opcode #x56)
                       (let ((target-spec (car stack)))
                         (unless (and (listp target-spec) (eq (first target-spec) :constant))
                           (error "JUMP target is not :constant at PC ~X." pc))
                         (let ((target-pc (second target-spec)))
                           (unless (integerp target-pc) (error "JUMP target PC is not an integer at PC ~X." pc))
                           (unless (< target-pc (length code)) (error "JUMP target PC ~X out of bounds at PC ~X." target-pc pc))
                           (unless (= (aref code target-pc) #x5B) (error "JUMP destination ~X is not JUMPDEST (Opcode: ~X)." target-pc (aref code target-pc)))
                           ;; Push the next state (jump target)
                           (push (list target-pc (cdr stack) next-visited) control-stack))))

                      ;; --- JUMPI ---
                      ((= opcode #x57)
                       (let ((target-spec (car stack)) ; Target PC is popped first
                             (condition-spec (cadr stack))) ; Condition is popped second
                         (declare (ignore condition-spec)) ; Static analysis explores both
                         (unless (and (listp target-spec) (eq (first target-spec) :constant))
                           (error "JUMPI target is not :constant at PC ~X." pc))
                         (let ((target-pc (second target-spec))
                               (fallthrough-pc (+ pc 1))
                               (next-stack (cddr stack))) ; Pop 2 items
                           (unless (integerp target-pc) (error "JUMPI target PC is not an integer at PC ~X." pc))
                           (unless (< target-pc (length code)) (error "JUMPI target PC ~X out of bounds at PC ~X." target-pc pc))
                           (unless (= (aref code target-pc) #x5B) (error "JUMPI destination ~X is not JUMPDEST (Opcode: ~X)." target-pc (aref code target-pc)))

                           ;; Push both next states onto the control stack
                           ;; Push fallthrough path *first* so jump path is processed next (DFS behavior)
                           (push (list fallthrough-pc next-stack next-visited) control-stack)
                           (push (list target-pc next-stack next-visited) control-stack))))

                      ;; --- DUPx ---
                      ((<= #x80 opcode #x8F)
                       (let* ((dup-n (- opcode #x7F)) ; 1 for DUP1, 16 for DUP16
                              (dup-index (- dup-n 1))) ; 0-based index for nth
                         (unless (>= (length stack) dup-n) (error "DUP stack underflow at PC ~X." pc))
                         (let* ((dup-item (nth dup-index stack))
                                (new-stack (cons dup-item stack))
                                (next-pc (+ pc 1)))
                           (push (list next-pc new-stack next-visited) control-stack))))

                      ;; --- SWAPx ---
                      ((<= #x90 opcode #x9F)
                       (let* ((swap-n (- opcode #x8F)) ; 1 for SWAP1, 16 for SWAP16
                              (next-pc (+ pc 1)))
                         (unless (>= (length stack) (+ swap-n 1)) (error "SWAP stack underflow at PC ~X." pc)) ; Need N+1 items
                         (let ((new-stack (swap-stack stack swap-n)))
                           (push (list next-pc new-stack next-visited) control-stack))))

                      ;; --- PC ---
                      ((= opcode #x58)
                       (let ((new-stack (cons `(:constant ,pc) stack))
                             (next-pc (+ pc 1)))
                         (push (list next-pc new-stack next-visited) control-stack)))

                      ;; --- Default (Other allowed, non-branching, non-terminating opcodes) ---
                      (t
                       (let* ((next-pc (+ pc 1))
                              (remaining-stack (nthcdr consumed stack))
                              ;; Using :unknown placeholder - adjust if needed
                              (produced-items (loop repeat produced collect :unknown))
                              (new-stack (append produced-items remaining-stack)))
                         (push (list next-pc new-stack next-visited) control-stack)))

                      ))) ; End cond and let (next-visited)
              ;; --- Error Handling for this specific path ---
              (error (c)
                ;; Log the error and prune this path by not pushing anything
                (warn "Error processing state (PC ~X): ~A. Pruning path." pc c)
                ;; The loop will continue with the next state from control-stack
                )))) ; End handler-case and let* (opcode/op-info)
          ))) ; End do and loop

    ;; Loop finished - exploration complete
    (format t "~&DFS exploration complete.~%")
  t) ; Return T indicating completion
)

;; Example Usage (requires *opcode-table* to be initialized):
;; (initialize-opcode-table)
;; (let ((bytecode #( #x60 #x01 ; PUSH1 0x01
;;                    #x60 #x02 ; PUSH1 0x02
;;                    #x01     ; ADD
;;                    #x60 #x0A ; PUSH1 0x0A (target)
;;                    #x57     ; JUMPI
;;                    #x60 #xFF ; PUSH1 0xFF (fallthrough path)
;;                    #x00     ; STOP (fallthrough path)
;;                    #x00     ; padding
;;                    #x00     ; padding
;;                    #x00     ; padding
;;                    #x5B     ; JUMPDEST (target path)
;;                    #x00     ; STOP (target path)
;;                    )))
;;   (iterative-dfs-walk-code bytecode 0))
;;

;; **Explanation of Changes:**

;; 1.  **`control-stack`:** A list is used to hold the states `(list pc stack visited)` that need processing.
;; 2.  **`loop while control-stack`:** The main loop continues as long as there are states to explore.
;; 3.  **`pop` State:** Each iteration starts by popping a state off the `control-stack`.
;; 4.  **Pre-Checks:** Checks for PC bounds, depth limit, and cycles (using the `visited` list specific to the path) are done before processing the opcode. If a check fails, `continue` skips to the next iteration without processing the current invalid/cyclic state.
;; 5.  **`handler-case`:** Wraps the main opcode processing logic. If an error occurs (like stack underflow, disallowed opcode, bad JUMP target) during the processing of *one state*, it's caught, a warning is printed, and the loop continues with the next state from the `control-stack`. This makes the overall exploration more robust to errors on specific paths. Critical errors like disallowed opcodes now use `error` within the handler-case block to signal a more severe problem if desired, but you could change them back to `warn` + `continue` if you want to ignore disallowed opcodes on a path.
;; 6.  **Pushing Next States:** Instead of recursive calls, the code calculates the next state(s) (`next-pc`, `new-stack`, `next-visited`) and pushes them onto the `control-stack`.
;; 7.  **`JUMPI` Handling:** Crucially, `JUMPI` pushes *both* the fallthrough state and the jump target state onto the `control-stack`. The fallthrough state is pushed first, so the jump target state (pushed second) is processed next, maintaining the Depth-First Search order.
;; 8.  **Termination:** Terminating opcodes simply don't push any new state, effectively ending that path. The loop continues until the `control-stack` is empty.
;; 9.  **Placeholders:** `:unknown` is used as a placeholder for results of operations in the default case. You might want a more sophisticated representation depending on your analysis goals.
;; 10. **Error vs. Warn:** I've used `error` for conditions that likely indicate fundamentally broken bytecode (disallowed opcode, bad jump target, push read OOB) and `warn` for conditions that prune a specific path (cycle, depth limit, runtime stack error). You can adjust this based on how strictly you want the analysis to fail.

;; This iterative version achieves the same DFS exploration as the recursive one but is safe from system stack overflows. Remember to ensure `initialize-opcode-table` is called before running the walk
