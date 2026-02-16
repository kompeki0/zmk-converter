/*
 * SPDX-License-Identifier: MIT
 */
#define DT_DRV_COMPAT zmk_behavior_tetris

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>

#include <drivers/behavior.h>

#include <zmk/behavior.h>
#include <zmk/events/keycode_state_changed.h>

#include <dt-bindings/zmk/keys.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

/* ==============================
 * Tunables
 * ============================== */
#define BOARD_W 10
#define BOARD_H 10

/* Editor line layout (0-based):
 * 0: title
 * 1: score line
 * 2: blank
 * 3..: board rows (H lines)
 */
#define BOARD_TOP_LINE_INDEX 3

#define MAX_UPDATE_LINES 16
#define UPDATE_TEXT_MAX 32  /* score line etc */

static uint16_t idle_before_fall_ms = 2000;
static uint16_t fall_interval_ms    = 700;

/* clear effect */
static uint8_t  clear_frames   = 4;   // blink count
static uint16_t clear_frame_ms = 110; // blink interval

/* extra delays you requested */
static uint16_t post_clear_spawn_delay_ms = 260;  // after rows cleared, before spawning next
static uint16_t post_land_spawn_delay_ms  = 180;  // normal landing -> spawn delay
static uint16_t post_hard_drop_delay_ms   = 260;  // hard drop landing -> spawn delay

/* delays for editor ops (stability) */
static uint32_t delay_for_char(char c) { return (c == '\n') ? 25 : 6; }
static uint32_t delay_nav(void) { return 12; }
static uint32_t delay_action(void) { return 18; }

/* ==============================
 * Key helpers (event-based)
 * ============================== */
static inline void press(uint32_t keycode) {
    raise_zmk_keycode_state_changed_from_encoded(keycode, true, (uint32_t)k_uptime_get());
}
static inline void release(uint32_t keycode) {
    raise_zmk_keycode_state_changed_from_encoded(keycode, false, (uint32_t)k_uptime_get());
}
static inline void tap(uint32_t keycode) {
    press(keycode);
    k_msleep(1);
    release(keycode);
}
static inline void tap_with_mod(uint32_t mod, uint32_t key) {
    press(mod);
    k_msleep(1);
    tap(key);
    k_msleep(1);
    release(mod);
}

/* ==============================
 * Text typing
 * ============================== */
static bool char_to_keycode(char c, uint32_t *out) {
    switch (c) {
    case 'x': *out = X; return true;
    case '.': *out = DOT; return true;
    case ' ': *out = SPACE; return true;
    case '\n': *out = ENTER; return true;

    /* JIS: '=' is UNDER in your environment */
    case '=': *out = UNDER; return true;
    case '-': *out = MINUS; return true;

    case '0': *out = N0; return true;
    case '1': *out = N1; return true;
    case '2': *out = N2; return true;
    case '3': *out = N3; return true;
    case '4': *out = N4; return true;
    case '5': *out = N5; return true;
    case '6': *out = N6; return true;
    case '7': *out = N7; return true;
    case '8': *out = N8; return true;
    case '9': *out = N9; return true;

    /* lowercase letters */
    case 'a': *out = A; return true;
    case 'b': *out = B; return true;
    case 'c': *out = C; return true;
    case 'd': *out = D; return true;
    case 'e': *out = E; return true;
    case 'f': *out = F; return true;
    case 'g': *out = G; return true;
    case 'h': *out = H; return true;
    case 'i': *out = I; return true;
    case 'j': *out = J; return true;
    case 'k': *out = K; return true;
    case 'l': *out = L; return true;
    case 'm': *out = M; return true;
    case 'n': *out = N; return true;
    case 'o': *out = O; return true;
    case 'p': *out = P; return true;
    case 'q': *out = Q; return true;
    case 'r': *out = R; return true;
    case 's': *out = S; return true;
    case 't': *out = T; return true;
    case 'u': *out = U; return true;
    case 'v': *out = V; return true;
    case 'w': *out = W; return true;
    case 'y': *out = Y; return true;
    case 'z': *out = Z; return true;

    default: return false;
    }
}

/* ==============================
 * Game state (locked board + falling piece)
 * ============================== */
static uint8_t board_locked[BOARD_H][BOARD_W]; // 0/1

enum tetromino {
    TET_I = 0,
    TET_O = 1,
    TET_T = 2,
    TET_S = 3,
    TET_Z = 4,
    TET_J = 5,
    TET_L = 6,
    TET_COUNT
};

struct piece_state {
    int x;          // top-left of 4x4 mask on board
    int y;
    uint8_t type;   // enum tetromino
    uint8_t rot;    // 0..3
};

static struct piece_state falling;
static bool has_falling; /* false during spawn-delay to avoid showing next piece */
static bool paused;

/* score */
static uint32_t score;
static uint16_t lines_cleared_total;

/* hold/keep */
static int8_t hold_type;     /* -1 none */
static bool hold_used;       /* one hold per piece */

/* queued inputs while rendering / clear animation / spawn delay */
static int  pending_dx;
static int  pending_rot_cw;
static int  pending_rot_ccw;
static bool pending_hard_drop;
static int  pending_soft_drop;
static bool pending_hold;
static uint32_t last_input_ms;

/* line clear state */
static bool clearing;
static uint16_t clear_mask;   // row bits
static uint8_t clear_step;

/* spawn delay */
static uint16_t pending_spawn_delay_ms;
static bool last_land_was_harddrop;

/* ==============================
 * 7-bag (shuffle 7, then pop)
 * ============================== */
static uint8_t bag[TET_COUNT];
static uint8_t bag_idx;

static void refill_and_shuffle_bag(void) {
    for (uint8_t i = 0; i < TET_COUNT; i++) bag[i] = i;

    /* Fisher-Yates shuffle */
    for (int i = TET_COUNT - 1; i > 0; i--) {
        uint32_t r = sys_rand32_get();
        int j = (int)(r % (uint32_t)(i + 1));
        uint8_t tmp = bag[i];
        bag[i] = bag[j];
        bag[j] = tmp;
    }
    bag_idx = 0;
}

static uint8_t bag_next_type(void) {
    if (bag_idx >= TET_COUNT) refill_and_shuffle_bag();
    return bag[bag_idx++];
}

static uint8_t bag_peek_next_type(void) {
    if (bag_idx >= TET_COUNT) {
        /* NOTE: keep deterministic-ish; refill now */
        refill_and_shuffle_bag();
    }
    return bag[bag_idx];
}

/* display helper */
static char tet_char(int t) {
    switch (t) {
    case TET_I: return 'i';
    case TET_O: return 'o';
    case TET_T: return 't';
    case TET_S: return 's';
    case TET_Z: return 'z';
    case TET_J: return 'j';
    case TET_L: return 'l';
    default: return '.';
    }
}

/* ==============================
 * 4x4 masks (bit 0 = (0,0), bit 15 = (3,3))
 * ============================== */
#define BIT_AT(r, c) ((uint16_t)(1u << (((r) * 4) + (c))))
static inline bool mask_has(uint16_t m, int r, int c) { return (m & BIT_AT(r, c)) != 0; }

static const uint16_t SHAPE[TET_COUNT][4] = {
    /* I */
    {
        BIT_AT(1,0) | BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(1,3),
        BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(2,2) | BIT_AT(3,2),
        BIT_AT(2,0) | BIT_AT(2,1) | BIT_AT(2,2) | BIT_AT(2,3),
        BIT_AT(0,1) | BIT_AT(1,1) | BIT_AT(2,1) | BIT_AT(3,1),
    },
    /* O */
    {
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(2,1) | BIT_AT(2,2),
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(2,1) | BIT_AT(2,2),
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(2,1) | BIT_AT(2,2),
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(2,1) | BIT_AT(2,2),
    },
    /* T */
    {
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,2),
        BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(2,2) | BIT_AT(1,3),
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(0,2),
        BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(2,2) | BIT_AT(1,1),
    },
    /* S */
    {
        BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,1) | BIT_AT(2,2),
        BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,3),
        BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,1) | BIT_AT(2,2),
        BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,3),
    },
    /* Z */
    {
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(2,2) | BIT_AT(2,3),
        BIT_AT(0,3) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,2),
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(2,2) | BIT_AT(2,3),
        BIT_AT(0,3) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,2),
    },
    /* J (fixed) */
    {
        /* rot 0: JJJ / J..  */
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,3),
        /* rot 1: .J. / .J. / JJ.  (出っ張りが左下) */
        BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(2,2) | BIT_AT(2,1),
        /* rot 2: ..J / JJJ */
        BIT_AT(0,1) | BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(1,3),
        /* rot 3: .JJ / .J. / .J.  (出っ張りが右上) */
        BIT_AT(0,2) | BIT_AT(0,3) | BIT_AT(1,2) | BIT_AT(2,2),
    },
    /* L (fixed) */
    {
        /* rot 0: LLL / ..L */
        BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(1,3) | BIT_AT(2,1),
        /* rot 1: .L. / .L. / .LL  (出っ張りが右下) */
        BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(2,2) | BIT_AT(2,3),
        /* rot 2: L.. / LLL */
        BIT_AT(0,3) | BIT_AT(1,1) | BIT_AT(1,2) | BIT_AT(1,3),
        /* rot 3: LL. / .L. / .L.  (出っ張りが左上) */
        BIT_AT(0,1) | BIT_AT(0,2) | BIT_AT(1,2) | BIT_AT(2,2),
    },
};

/* ==============================
 * Collision / placement
 * ============================== */
static bool can_place(uint8_t type, uint8_t rot, int x, int y) {
    uint16_t m = SHAPE[type][rot & 3];

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            if (!mask_has(m, r, c)) continue;

            int br = y + r;
            int bc = x + c;
            if (bc < 0 || bc >= BOARD_W || br < 0 || br >= BOARD_H) return false;
            if (board_locked[br][bc]) return false;
        }
    }
    return true;
}

/* ==============================
 * Wall kick (SRS-like) CW + CCW
 * ============================== */
static const int8_t KICK_JLSTZ_CW[4][5][2] = {
    {{0,0},{-1,0},{-1,1},{0,-2},{-1,-2}}, // 0->1
    {{0,0},{ 1,0},{ 1,-1},{0,2},{ 1,2}},  // 1->2
    {{0,0},{ 1,0},{ 1,1},{0,-2},{ 1,-2}}, // 2->3
    {{0,0},{-1,0},{-1,-1},{0,2},{-1,2}},  // 3->0
};
static const int8_t KICK_JLSTZ_CCW[4][5][2] = {
    {{0,0},{ 1,0},{ 1,1},{0,-2},{ 1,-2}}, // 0->3
    {{0,0},{ 1,0},{ 1,-1},{0,2},{ 1,2}},  // 1->0
    {{0,0},{-1,0},{-1,1},{0,-2},{-1,-2}}, // 2->1
    {{0,0},{-1,0},{-1,-1},{0,2},{-1,2}},  // 3->2
};

static const int8_t KICK_I_CW[4][5][2] = {
    {{0,0},{-2,0},{ 1,0},{-2,-1},{ 1,2}}, // 0->1
    {{0,0},{-1,0},{ 2,0},{-1,2},{ 2,-1}}, // 1->2
    {{0,0},{ 2,0},{-1,0},{ 2,1},{-1,-2}}, // 2->3
    {{0,0},{ 1,0},{-2,0},{ 1,-2},{-2,1}}, // 3->0
};
static const int8_t KICK_I_CCW[4][5][2] = {
    {{0,0},{-1,0},{ 2,0},{-1,2},{ 2,-1}}, // 0->3
    {{0,0},{ 2,0},{-1,0},{ 2,1},{-1,-2}}, // 1->0
    {{0,0},{ 1,0},{-2,0},{ 1,-2},{-2,1}}, // 2->1
    {{0,0},{-2,0},{ 1,0},{-2,-1},{ 1,2}}, // 3->2
};

static bool try_rotate(int dir /* +1 CW, -1 CCW */) {
    uint8_t type = falling.type;
    uint8_t r0 = falling.rot & 3;
    uint8_t r1 = (dir > 0) ? ((r0 + 1) & 3) : ((r0 + 3) & 3);

    if (type == TET_O) {
        if (can_place(type, r1, falling.x, falling.y)) { falling.rot = r1; return true; }
        return false;
    }

    const int8_t (*kicks)[2] = NULL;
    if (type == TET_I) kicks = (dir > 0) ? KICK_I_CW[r0] : KICK_I_CCW[r0];
    else kicks = (dir > 0) ? KICK_JLSTZ_CW[r0] : KICK_JLSTZ_CCW[r0];

    for (int i = 0; i < 5; i++) {
        int nx = falling.x + kicks[i][0];
        int ny = falling.y + kicks[i][1];
        if (can_place(type, r1, nx, ny)) {
            falling.x = nx;
            falling.y = ny;
            falling.rot = r1;
            return true;
        }
    }
    return false;
}

/* ==============================
 * Score line builder: "s 00000 l 000 n t k l"
 * ============================== */
static char score_prev[UPDATE_TEXT_MAX];
static char score_next[UPDATE_TEXT_MAX];

static void build_score_next(void) {
    uint32_t s = score;
    if (s > 99999) s = 99999;
    uint16_t l = lines_cleared_total;
    if (l > 999) l = 999;

    char nchar = tet_char((int)bag_peek_next_type());
    char kchar = (hold_type < 0) ? '.' : tet_char((int)hold_type);

    int w = 0;

    score_next[w++] = 's';
    score_next[w++] = ' ';
    score_next[w++] = '0' + ((s / 10000) % 10);
    score_next[w++] = '0' + ((s / 1000) % 10);
    score_next[w++] = '0' + ((s / 100) % 10);
    score_next[w++] = '0' + ((s / 10) % 10);
    score_next[w++] = '0' + (s % 10);

    score_next[w++] = ' ';
    score_next[w++] = 'l';
    score_next[w++] = ' ';
    score_next[w++] = '0' + ((l / 100) % 10);
    score_next[w++] = '0' + ((l / 10) % 10);
    score_next[w++] = '0' + (l % 10);

    score_next[w++] = ' ';
    score_next[w++] = 'n';
    score_next[w++] = ' ';
    score_next[w++] = nchar;

    score_next[w++] = ' ';
    score_next[w++] = 'h';
    score_next[w++] = ' ';
    score_next[w++] = kchar;

    score_next[w++] = ' ';
    score_next[w] = '\0';
}

static bool score_equals(void) {
    for (int i = 0; i < UPDATE_TEXT_MAX; i++) {
        if (score_prev[i] != score_next[i]) return false;
        if (score_next[i] == '\0') return true;
    }
    return true;
}
static void commit_score_line(void) {
    for (int i = 0; i < UPDATE_TEXT_MAX; i++) {
        score_prev[i] = score_next[i];
        if (score_next[i] == '\0') break;
    }
}

/* ==============================
 * Lock / clear / spawn
 * ============================== */
static void lock_falling(void) {
    uint16_t m = SHAPE[falling.type][falling.rot & 3];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            if (!mask_has(m, r, c)) continue;
            int br = falling.y + r;
            int bc = falling.x + c;
            if (br >= 0 && br < BOARD_H && bc >= 0 && bc < BOARD_W) board_locked[br][bc] = 1;
        }
    }
}

static uint16_t detect_full_lines(void) {
    uint16_t mask = 0;
    for (int r = 0; r < BOARD_H; r++) {
        bool full = true;
        for (int c = 0; c < BOARD_W; c++) {
            if (!board_locked[r][c]) { full = false; break; }
        }
        if (full) mask |= (1u << r);
    }
    return mask;
}

static uint8_t popcount16(uint16_t x) {
    uint8_t n = 0;
    while (x) { x &= (uint16_t)(x - 1); n++; }
    return n;
}

static void apply_line_clear(uint16_t mask) {
    if (!mask) return;

    int dst = BOARD_H - 1;
    for (int src = BOARD_H - 1; src >= 0; src--) {
        if (mask & (1u << src)) continue;
        if (dst != src) {
            for (int c = 0; c < BOARD_W; c++) board_locked[dst][c] = board_locked[src][c];
        }
        dst--;
    }
    for (int r = dst; r >= 0; r--) for (int c = 0; c < BOARD_W; c++) board_locked[r][c] = 0;
}

static void spawn_piece(void) {
    falling.type = bag_next_type();
    falling.rot  = 0;
    falling.x = 3;
    falling.y = 0;

    if (!can_place(falling.type, falling.rot, falling.x, falling.y)) {
        /* demo: wipe board on gameover */
        for (int r = 0; r < BOARD_H; r++) for (int c = 0; c < BOARD_W; c++) board_locked[r][c] = 0;

        /* reset bag/hold too */
        refill_and_shuffle_bag();
        hold_type = -1;
        hold_used = false;

        falling.type = bag_next_type();
        falling.rot  = 0;
        falling.x = 3;
        falling.y = 0;
    }

    /* new falling piece allows hold again */
    hold_used = false;
}

/* Keep operation:
 * - once per piece (hold_used)
 * - swap with hold slot, or store current then spawn new
 */
static void do_hold_action(void) {
    if (!has_falling) return;
    if (hold_used) return;

    has_falling = false; /* hide while we swap to avoid visual glitch */

    if (hold_type < 0) {
        hold_type = (int8_t)falling.type;
        spawn_piece(); /* consume next from bag */
    } else {
        int8_t tmp = hold_type;
        hold_type = (int8_t)falling.type;
        falling.type = (uint8_t)tmp;

        falling.rot = 0;
        falling.x = 3;
        falling.y = 0;

        if (!can_place(falling.type, falling.rot, falling.x, falling.y)) {
            /* treat as gameover-like: wipe board and reset */
            for (int r = 0; r < BOARD_H; r++) for (int c = 0; c < BOARD_W; c++) board_locked[r][c] = 0;
            refill_and_shuffle_bag();
            hold_type = -1;
            hold_used = false;
            spawn_piece();
        }
    }

    hold_used = true;
    has_falling = true;
}

/* ==============================
 * Renderer: diff lines
 * ============================== */
struct update_line {
    int line_index;
    char text[UPDATE_TEXT_MAX];
};

static char render_prev[BOARD_H][BOARD_W + 2];
static char render_next[BOARD_H][BOARD_W + 2];

static void build_row_string(int row, char out[BOARD_W + 2]) {
    /* clear effect overrides; do NOT show next piece while clearing */
    if (clearing && (clear_mask & (1u << row))) {
        bool on = ((clear_step % 2) == 0);
        for (int c = 0; c < BOARD_W; c++) out[c] = on ? '=' : '.';
        out[BOARD_W] = ' ';
        out[BOARD_W + 1] = '\0';
        return;
    }

    for (int c = 0; c < BOARD_W; c++) out[c] = board_locked[row][c] ? 'x' : '.';

    /* overlay falling only if allowed */
    if (has_falling && !clearing) {
        uint16_t m = SHAPE[falling.type][falling.rot & 3];
        for (int r = 0; r < 4; r++) {
            int br = falling.y + r;
            if (br != row) continue;
            for (int c = 0; c < 4; c++) {
                if (!mask_has(m, r, c)) continue;
                int bc = falling.x + c;
                if (bc >= 0 && bc < BOARD_W) out[bc] = 'x';
            }
        }
    }

    out[BOARD_W] = ' ';
    out[BOARD_W + 1] = '\0';
}

static void rebuild_render_next(void) {
    for (int r = 0; r < BOARD_H; r++) build_row_string(r, render_next[r]);
}

static bool row_equals(const char *a, const char *b) {
    for (int i = 0; i < BOARD_W + 2; i++) {
        if (a[i] != b[i]) return false;
        if (a[i] == '\0') break;
    }
    return true;
}

static uint8_t make_board_diff(struct update_line out[MAX_UPDATE_LINES]) {
    uint8_t n = 0;
    for (int r = 0; r < BOARD_H; r++) {
        if (row_equals(render_prev[r], render_next[r])) continue;
        if (n >= MAX_UPDATE_LINES) break;

        out[n].line_index = BOARD_TOP_LINE_INDEX + r;

        int w = 0;
        for (int i = 0; i < BOARD_W + 2 && w + 1 < UPDATE_TEXT_MAX; i++) {
            out[n].text[w++] = render_next[r][i];
            if (render_next[r][i] == '\0') break;
        }
        out[n].text[UPDATE_TEXT_MAX - 1] = '\0';

        /* optimistic commit */
        for (int i = 0; i < BOARD_W + 2; i++) {
            render_prev[r][i] = render_next[r][i];
            if (render_next[r][i] == '\0') break;
        }

        n++;
    }
    return n;
}

/* ==============================
 * Render engine (async)
 * ============================== */
enum render_mode { RENDER_IDLE = 0, RENDER_CLEAR_EDITOR, RENDER_TYPE_FULL, RENDER_REPLACE_LINE_SCRIPT };
enum clear_phase { CLP_CTRL_A = 0, CLP_BS, CLP_DONE };
enum script_phase {
    SPH_CTRL_HOME = 0, SPH_DOWN_REPEAT, SPH_HOME, SPH_SHIFT_END_PRESS, SPH_END_TAP,
    SPH_SHIFT_END_RELEASE, SPH_BACKSPACE, SPH_TYPE_LINE, SPH_DONE
};
enum request_type { REQ_NONE = 0, REQ_CLEAR_ONLY, REQ_RESET_AND_DRAW };

struct render_state {
    bool inited;
    bool running;

    enum request_type req;
    enum render_mode mode;

    enum clear_phase clear_phase;

    const char *text;
    size_t text_idx;

    enum script_phase phase;
    int down_remaining;
    const char *line_text;
    size_t line_idx;

    struct update_line batch[MAX_UPDATE_LINES];
    uint8_t batch_len;
    uint8_t batch_pos;

    struct k_work_delayable work;
};

static struct render_state rs;

static struct k_work_delayable gravity_work;
static struct k_work_delayable clear_work;
static struct k_work_delayable spawn_work;

/* forward */
static void apply_pending_and_redraw_once(void);

static void stop_render(void) {
    rs.running = false;
    rs.req = REQ_NONE;
    rs.mode = RENDER_IDLE;
    rs.batch_len = 0;
    rs.batch_pos = 0;
    k_work_cancel_delayable(&rs.work);
}

static void start_clear_editor_async(enum request_type req_after) {
    rs.req = req_after;
    rs.mode = RENDER_CLEAR_EDITOR;
    rs.clear_phase = CLP_CTRL_A;
    rs.running = true;
    k_work_reschedule(&rs.work, K_NO_WAIT);
}

static void start_full_text_async(const char *text) {
    rs.mode = RENDER_TYPE_FULL;
    rs.text = text;
    rs.text_idx = 0;
    rs.running = true;
    k_work_reschedule(&rs.work, K_NO_WAIT);
}

static void start_replace_line_script(int line_index_zero_based, const char *line) {
    rs.mode = RENDER_REPLACE_LINE_SCRIPT;
    rs.phase = SPH_CTRL_HOME;
    rs.down_remaining = line_index_zero_based;
    rs.line_text = line;
    rs.line_idx = 0;

    rs.running = true;
    k_work_reschedule(&rs.work, K_NO_WAIT);
}

static void start_batch(struct update_line *lines, uint8_t len) {
    if (len == 0) return;
    if (len > MAX_UPDATE_LINES) len = MAX_UPDATE_LINES;

    for (uint8_t i = 0; i < len; i++) rs.batch[i] = lines[i];
    rs.batch_len = len;
    rs.batch_pos = 0;

    start_replace_line_script(rs.batch[0].line_index, rs.batch[0].text);
}

/* full frame buffer */
static char full_frame_buf[512];

static void build_full_frame_text(void) {
    size_t w = 0;

    const char *hdr = "tetris zmk\n";
    for (size_t i = 0; hdr[i] && w + 1 < sizeof(full_frame_buf); i++) full_frame_buf[w++] = hdr[i];

    build_score_next();
    for (size_t i = 0; score_next[i] && w + 1 < sizeof(full_frame_buf); i++) full_frame_buf[w++] = score_next[i];
    if (w + 1 < sizeof(full_frame_buf)) full_frame_buf[w++] = '\n';
    if (w + 1 < sizeof(full_frame_buf)) full_frame_buf[w++] = '\n';

    rebuild_render_next();
    for (int r = 0; r < BOARD_H; r++) {
        for (int i = 0; render_next[r][i] && w + 1 < sizeof(full_frame_buf); i++) full_frame_buf[w++] = render_next[r][i];
        if (w + 1 < sizeof(full_frame_buf)) full_frame_buf[w++] = '\n';
    }

    full_frame_buf[w] = '\0';
}


/* build a combined diff batch: score line + board lines */
static void request_diff_render(void) {
    if (rs.running) return;

    struct update_line lines[MAX_UPDATE_LINES];
    uint8_t len = 0;

    /* score line (line 1) */
    build_score_next();
    if (!score_equals() && len < MAX_UPDATE_LINES) {
        lines[len].line_index = 1;
        for (int i = 0; i < UPDATE_TEXT_MAX; i++) {
            lines[len].text[i] = score_next[i];
            if (score_next[i] == '\0') break;
        }
        lines[len].text[UPDATE_TEXT_MAX - 1] = '\0';
        commit_score_line();
        len++;
    }

    /* board diff */
    rebuild_render_next();
    struct update_line board_lines[MAX_UPDATE_LINES];
    uint8_t b_len = make_board_diff(board_lines);

    for (uint8_t i = 0; i < b_len && len < MAX_UPDATE_LINES; i++) {
        lines[len++] = board_lines[i];
    }

    if (len == 0) return;
    start_batch(lines, len);
}


static void force_redraw_all(void) {
    /* render_prevを全消しして差分を“全行”にする */
    for (int r = 0; r < BOARD_H; r++) {
        for (int i = 0; i < BOARD_W + 2; i++) render_prev[r][i] = '\0';
    }
    score_prev[0] = '\0'; /* scoreも必ず更新させる */

    request_diff_render();
}

static void render_work_handler(struct k_work *work) {
    ARG_UNUSED(work);
    if (!rs.running) return;

    if (rs.mode == RENDER_CLEAR_EDITOR) {
        switch (rs.clear_phase) {
        case CLP_CTRL_A:
            tap_with_mod(LCTRL, A);
            rs.clear_phase = CLP_BS;
            k_work_reschedule(&rs.work, K_MSEC(delay_action()));
            return;
        case CLP_BS:
            tap(BACKSPACE);
            rs.clear_phase = CLP_DONE;
            k_work_reschedule(&rs.work, K_MSEC(delay_action()));
            return;
        case CLP_DONE:
        default: {
            enum request_type next = rs.req;
            rs.req = REQ_NONE;

            if (next == REQ_RESET_AND_DRAW) {
                start_full_text_async(full_frame_buf);
                return;
            }

            rs.running = false;
            rs.mode = RENDER_IDLE;
            rs.batch_len = 0;
            rs.batch_pos = 0;

            apply_pending_and_redraw_once();
            return;
        }
        }
    }

    if (rs.mode == RENDER_TYPE_FULL) {
        char c = rs.text[rs.text_idx];
        if (c == '\0') {
            rebuild_render_next();
            for (int r = 0; r < BOARD_H; r++) {
                for (int i = 0; i < BOARD_W + 2; i++) {
                    render_prev[r][i] = render_next[r][i];
                    if (render_next[r][i] == '\0') break;
                }
            }

            /* score commit as well */
            build_score_next();
            commit_score_line();

            rs.running = false;
            rs.mode = RENDER_IDLE;
            rs.batch_len = 0;
            rs.batch_pos = 0;

            apply_pending_and_redraw_once();
            return;
        }

        uint32_t kc;
        if (char_to_keycode(c, &kc)) tap(kc);
        rs.text_idx++;
        k_work_reschedule(&rs.work, K_MSEC(delay_for_char(c)));
        return;
    }

    if (rs.mode == RENDER_REPLACE_LINE_SCRIPT) {
        switch (rs.phase) {
        case SPH_CTRL_HOME:
            tap_with_mod(LCTRL, HOME);
            rs.phase = SPH_DOWN_REPEAT;
            k_work_reschedule(&rs.work, K_MSEC(delay_nav()));
            return;

        case SPH_DOWN_REPEAT:
            if (rs.down_remaining > 0) {
                tap(DOWN);
                rs.down_remaining--;
                k_work_reschedule(&rs.work, K_MSEC(delay_nav()));
                return;
            }
            rs.phase = SPH_HOME;
            k_work_reschedule(&rs.work, K_MSEC(delay_nav()));
            return;

        case SPH_HOME:
            tap(HOME);
            rs.phase = SPH_SHIFT_END_PRESS;
            k_work_reschedule(&rs.work, K_MSEC(delay_action()));
            return;

        case SPH_SHIFT_END_PRESS:
            press(LSHIFT);
            rs.phase = SPH_END_TAP;
            k_work_reschedule(&rs.work, K_MSEC(4));
            return;

        case SPH_END_TAP:
            tap(END);
            rs.phase = SPH_SHIFT_END_RELEASE;
            k_work_reschedule(&rs.work, K_MSEC(4));
            return;

        case SPH_SHIFT_END_RELEASE:
            release(LSHIFT);
            rs.phase = SPH_BACKSPACE;
            k_work_reschedule(&rs.work, K_MSEC(delay_action()));
            return;

        case SPH_BACKSPACE:
            tap(BACKSPACE);
            rs.phase = SPH_TYPE_LINE;
            rs.line_idx = 0;
            k_work_reschedule(&rs.work, K_MSEC(delay_action()));
            return;

        case SPH_TYPE_LINE: {
            char c = rs.line_text[rs.line_idx];
            if (c == '\0') {
                rs.phase = SPH_DONE;
                k_work_reschedule(&rs.work, K_MSEC(delay_action()));
                return;
            }
            uint32_t kc;
            if (char_to_keycode(c, &kc)) tap(kc);
            rs.line_idx++;
            k_work_reschedule(&rs.work, K_MSEC(delay_for_char(c)));
            return;
        }

        case SPH_DONE:
        default:
            if (rs.batch_pos + 1 < rs.batch_len) {
                rs.batch_pos++;
                start_replace_line_script(rs.batch[rs.batch_pos].line_index,
                                          rs.batch[rs.batch_pos].text);
                return;
            }

            rs.running = false;
            rs.mode = RENDER_IDLE;
            rs.batch_len = 0;
            rs.batch_pos = 0;

            apply_pending_and_redraw_once();
            return;
        }
    }

    rs.running = false;
    rs.mode = RENDER_IDLE;
    rs.batch_len = 0;
    rs.batch_pos = 0;
}

/* ==============================
 * Gravity / Clear / Spawn scheduling
 * ============================== */
static void schedule_gravity_idle(void) {
    k_work_reschedule(&gravity_work, K_MSEC(idle_before_fall_ms));
}
static void schedule_gravity_interval(void) {
    k_work_reschedule(&gravity_work, K_MSEC(fall_interval_ms));
}

static void on_user_input_common(void) {
    last_input_ms = (uint32_t)k_uptime_get();
    schedule_gravity_idle();
}

static void begin_spawn_delay(uint16_t delay_ms) {
    has_falling = false;                 /* hide next piece during delay */
    pending_spawn_delay_ms = delay_ms;
    request_diff_render();               /* redraw board without piece if needed */
    k_work_reschedule(&spawn_work, K_MSEC(delay_ms));
}

static void begin_clear_animation(uint16_t mask) {
    clearing = true;
    clear_mask = mask;
    clear_step = 0;

    request_diff_render();
    k_work_reschedule(&clear_work, K_MSEC(clear_frame_ms));
}

static bool do_fall_one(void) {
    int ny = falling.y + 1;
    if (has_falling && can_place(falling.type, falling.rot, falling.x, ny)) {
        falling.y = ny;
        return true;
    }
    return false;
}

static void on_piece_landed(void) {
    lock_falling();
    has_falling = false;

    uint16_t mask = detect_full_lines();
    if (mask) {
        uint8_t cleared = popcount16(mask);
        lines_cleared_total = (uint16_t)(lines_cleared_total + cleared);

        /* 1=100,2=300,3=500,4=800 */
        static const uint16_t tbl[5] = {0, 100, 300, 500, 800};
        score += tbl[cleared <= 4 ? cleared : 4];

        begin_clear_animation(mask);
        return;
    }

    begin_spawn_delay(last_land_was_harddrop ? post_hard_drop_delay_ms : post_land_spawn_delay_ms);
}

static void hard_drop_and_land(void) {
    if (!has_falling) return;
    while (do_fall_one()) { /* drop */ }
    on_piece_landed();
}

/* clear animation worker */
static void clear_work_handler(struct k_work *work) {
    ARG_UNUSED(work);
    if (paused) {
        k_work_reschedule(&clear_work, K_MSEC(100));
        return;
    }
    if (!clearing) return;

    if (rs.running) {
        k_work_reschedule(&clear_work, K_MSEC(30));
        return;
    }

    clear_step++;

    if (clear_step < clear_frames) {
        request_diff_render();
        k_work_reschedule(&clear_work, K_MSEC(clear_frame_ms));
        return;
    }

    uint16_t mask = clear_mask;

    clearing = false;
    clear_mask = 0;
    clear_step = 0;

    apply_line_clear(mask);

    begin_spawn_delay(post_clear_spawn_delay_ms);
}

/* spawn delay worker */
static void spawn_work_handler(struct k_work *work) {
    ARG_UNUSED(work);

    if (paused) {
        k_work_reschedule(&spawn_work, K_MSEC(100));
        return;
    }
    if (clearing) {
        k_work_reschedule(&spawn_work, K_MSEC(30));
        return;
    }
    if (rs.running) {
        k_work_reschedule(&spawn_work, K_MSEC(30));
        return;
    }

    spawn_piece();
    has_falling = true;

    request_diff_render();
    schedule_gravity_idle();
}

/* gravity worker */
static void gravity_work_handler(struct k_work *work) {
    ARG_UNUSED(work);
    if (paused) {
        /* paused: do nothing, keep stopped */
        k_work_reschedule(&gravity_work, K_MSEC(100));
        return;
    }
    if (clearing) {
        k_work_reschedule(&gravity_work, K_MSEC(50));
        return;
    }
    if (!has_falling) {
        k_work_reschedule(&gravity_work, K_MSEC(50));
        return;
    }

    uint32_t now = (uint32_t)k_uptime_get();
    uint32_t since_input = now - last_input_ms;

    if (since_input < idle_before_fall_ms) {
        uint32_t remain = idle_before_fall_ms - since_input;
        if (remain < 50) remain = 50;
        k_work_reschedule(&gravity_work, K_MSEC(remain));
        return;
    }

    if (rs.running) {
        k_work_reschedule(&gravity_work, K_MSEC(30));
        return;
    }

    if (do_fall_one()) {
        request_diff_render();
        schedule_gravity_interval();
        return;
    }

    last_land_was_harddrop = false;
    on_piece_landed();
}

/* ==============================
 * Input handling (queue while rendering / clearing / spawn-delay)
 * ============================== */
static void apply_pending_and_redraw_once(void) {
    if (rs.running || clearing) return;
    if (!has_falling) return;

    bool changed = false;

    if (pending_hold) {
        pending_hold = false;
        do_hold_action();
        request_diff_render();
        /* hold consumes action; still allow other queued inputs next cycle */
        return;
    }

    /* dx */
    if (pending_dx != 0) {
        int dx = pending_dx;
        pending_dx = 0;

        int nx = falling.x + dx;
        if (can_place(falling.type, falling.rot, nx, falling.y)) {
            falling.x = nx;
            changed = true;
        }
    }

    /* rotate: CCW then CW */
    while (pending_rot_ccw > 0) {
        pending_rot_ccw--;
        if (try_rotate(-1)) changed = true;
    }
    while (pending_rot_cw > 0) {
        pending_rot_cw--;
        if (try_rotate(+1)) changed = true;
    }

    /* hard drop overrides */
    if (pending_hard_drop) {
        pending_hard_drop = false;
        last_land_was_harddrop = true;
        hard_drop_and_land();
        return;
    }

    /* soft drop */
    if (pending_soft_drop > 0) {
        int n = pending_soft_drop;
        pending_soft_drop = 0;
        for (int i = 0; i < n; i++) {
            if (do_fall_one()) {
                changed = true;
            } else {
                last_land_was_harddrop = false;
                on_piece_landed();
                return;
            }
        }
        changed = true;
    }

    if (changed) request_diff_render();
}

static void on_user_dx(int dx) {
    if (paused) return;
    on_user_input_common();
    if (rs.running || clearing || !has_falling) { pending_dx += dx; return; }

    int nx = falling.x + dx;
    if (can_place(falling.type, falling.rot, nx, falling.y)) {
        falling.x = nx;
        request_diff_render();
    }
}

static void on_user_rotate(int dir) {
    on_user_input_common();
    if (rs.running || clearing || !has_falling) {
        if (dir > 0) pending_rot_cw++;
        else pending_rot_ccw++;
        return;
    }
    if (try_rotate(dir)) request_diff_render();
}

static void on_user_soft_drop(void) {
    on_user_input_common();
    if (rs.running || clearing || !has_falling) { pending_soft_drop++; return; }

    if (do_fall_one()) {
        request_diff_render();
    } else {
        last_land_was_harddrop = false;
        on_piece_landed();
    }
}

static void on_user_hard_drop(void) {
    on_user_input_common();
    if (rs.running || clearing || !has_falling) { pending_hard_drop = true; return; }
    last_land_was_harddrop = true;
    hard_drop_and_land();
}

static void on_user_hold(void) {
    on_user_input_common();
    if (rs.running || clearing || !has_falling) { pending_hold = true; return; }
    do_hold_action();
    request_diff_render();
}

/* ==============================
 * Init/reset
 * ============================== */
static void reset_game(void) {
    paused = false;
    for (int r = 0; r < BOARD_H; r++) {
        for (int c = 0; c < BOARD_W; c++) board_locked[r][c] = 0;
        for (int i = 0; i < BOARD_W + 2; i++) render_prev[r][i] = '\0';
    }

    /* score */
    score = 0;
    lines_cleared_total = 0;
    score_prev[0] = '\0';

    /* bag + hold */
    refill_and_shuffle_bag();
    hold_type = -1;
    hold_used = false;

    pending_dx = 0;
    pending_rot_cw = 0;
    pending_rot_ccw = 0;
    pending_soft_drop = 0;
    pending_hard_drop = false;
    pending_hold = false;

    clearing = false;
    clear_mask = 0;
    clear_step = 0;

    last_land_was_harddrop = false;
    pending_spawn_delay_ms = 0;

    last_input_ms = (uint32_t)k_uptime_get();

    spawn_piece();
    has_falling = true;

    rebuild_render_next();
    for (int r = 0; r < BOARD_H; r++)
        for (int i = 0; i < BOARD_W + 2; i++)
            render_prev[r][i] = '\0';
}

/* ==============================
 * Behavior entry
 *
 * Commands:
 * 0: reset + async clear + async draw + start gravity (idle)
 * 1: async clear editor
 * 2: pause toggle
 * 3: redraw (score+board) without clearing editor
 * 10: left
 * 11: right
 * 12: rotate CW
 * 13: soft drop
 * 14: rotate CCW
 * 15: hard drop
 * 16: HOLD (keep)
 * ============================== */
static int on_pressed(struct zmk_behavior_binding *binding,
                      struct zmk_behavior_binding_event event) {
    ARG_UNUSED(event);

    uint32_t cmd = binding->param1;

    if (!rs.inited) {
        k_work_init_delayable(&rs.work, render_work_handler);
        k_work_init_delayable(&gravity_work, gravity_work_handler);
        k_work_init_delayable(&clear_work, clear_work_handler);
        k_work_init_delayable(&spawn_work, spawn_work_handler);
        rs.inited = true;
    }

    LOG_DBG("tetris cmd=%d", cmd);

    switch (cmd) {
    case 0:
        stop_render();
        k_work_cancel_delayable(&gravity_work);
        k_work_cancel_delayable(&clear_work);
        k_work_cancel_delayable(&spawn_work);

        reset_game();
        build_full_frame_text();
        start_clear_editor_async(REQ_RESET_AND_DRAW);

        schedule_gravity_idle();
        return ZMK_BEHAVIOR_OPAQUE;

    case 1:
        stop_render();
        k_work_cancel_delayable(&gravity_work);
        k_work_cancel_delayable(&clear_work);
        k_work_cancel_delayable(&spawn_work);

        start_clear_editor_async(REQ_CLEAR_ONLY);
        return ZMK_BEHAVIOR_OPAQUE;
    
    case 2: /* pause toggle */
        paused = !paused;
        if (paused) {
            /* stop game progression immediately */
            k_work_cancel_delayable(&gravity_work);
        } else {
            /* resume */
            schedule_gravity_idle();
        }
        /* 表示を変えないなら不要だが、状態ズレ対策で再描画はしておくと安心 */
        force_redraw_all();
        return ZMK_BEHAVIOR_OPAQUE;

    case 3: /* redraw */
        force_redraw_all();
        return ZMK_BEHAVIOR_OPAQUE;
    case 10:
        on_user_dx(-1);
        return ZMK_BEHAVIOR_OPAQUE;

    case 11:
        on_user_dx(+1);
        return ZMK_BEHAVIOR_OPAQUE;

    case 12:
        on_user_rotate(+1);
        return ZMK_BEHAVIOR_OPAQUE;

    case 13:
        on_user_soft_drop();
        return ZMK_BEHAVIOR_OPAQUE;

    case 14:
        on_user_rotate(-1);
        return ZMK_BEHAVIOR_OPAQUE;

    case 15:
        on_user_hard_drop();
        return ZMK_BEHAVIOR_OPAQUE;

    case 16:
        on_user_hold();
        return ZMK_BEHAVIOR_OPAQUE;

    default:
        return ZMK_BEHAVIOR_TRANSPARENT;
    }
}

static const struct behavior_driver_api api = {
    .binding_pressed = on_pressed,
    .binding_released = NULL,
};

#define INST(n) \
    BEHAVIOR_DT_INST_DEFINE(n, NULL, NULL, NULL, NULL, \
        POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, &api);

DT_INST_FOREACH_STATUS_OKAY(INST)
