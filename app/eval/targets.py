"""Benchmark targets: legal, mostly obscure things that genuinely exist somewhere public.

Each target = what a user would type (goal / category / description of "found") plus an
ANSWER SIGNATURE: a result counts as the target when its title (or url) matches `sig`.
`topic` is looser — a stored result that matches neither is JUNK (off-goal noise the
judge should have rejected). Difficulty is a rough prior of how many cycles a good agent
needs. Add targets freely; keep them legal (public domain / CC / free software / open data).
"""

BENCH = [
    # ---- movies -------------------------------------------------------------------
    {"id": "bbb-1080", "category": "movies", "difficulty": "easy",
     "goal": "Big Buck Bunny 1080p",
     "description": "the 2008 Blender open movie, 1080p or better, any container",
     "sig": r"big.?buck.?bunny.*(1080|2160|4k|60 ?fps)", "topic": r"buck.?bunny|blender"},
    {"id": "sintel-4k", "category": "movies", "difficulty": "medium",
     "goal": "Sintel Blender open movie 4K",
     "description": "the 4K (2160p) master or highest-quality release of the 2010 Blender "
                    "Foundation short film, surround audio preferred",
     "sig": r"sintel.*(2160|4k|uhd)|(2160|4k|uhd).*sintel", "topic": r"sintel|blender"},
    {"id": "notld-1968", "category": "movies", "difficulty": "medium",
     "goal": "Night of the Living Dead 1968 George Romero",
     "description": "the original 1968 public-domain film, best available restoration (the "
                    "4K/1080p scan of the original negative if possible), not the 1990 remake",
     "sig": r"night.of.the.living.dead.*(1968|romero|restor|criterion|4k|1080)",
     "topic": r"living.?dead|romero"},
    # ---- music ----------------------------------------------------------------------
    {"id": "kankyo-ongaku", "category": "music", "difficulty": "hard",
     "goal": "Kankyo Ongaku Japanese ambient environmental music 1980s compilation",
     "description": "the Light in the Attic 'Kankyō Ongaku' compilation (2019) OR complete "
                    "original 1980s Japanese ambient albums by Hiroshi Yoshimura, Satoshi "
                    "Ashikawa or Takashi Kokubo; lossless FLAC preferred",
     "sig": r"kanky[oō]|hiroshi.?yoshimura|satoshi.?ashikawa|takashi.?kokubo",
     "topic": r"kanky[oō]|yoshimura|ashikawa|kokubo|japanese.*ambient|ambient.*japan"},
    {"id": "nin-ghosts", "category": "music", "difficulty": "medium",
     "goal": "Nine Inch Nails Ghosts I-IV",
     "description": "the 2008 Creative-Commons instrumental album (all 36 tracks), FLAC or "
                    "the official multitrack/high-res release",
     "sig": r"(nine.?inch.?nails|\bnin\b).*ghosts|ghosts.*(nine.?inch.?nails|\bnin\b)",
     "topic": r"nine.?inch|\bnin\b|ghosts|reznor"},
    {"id": "open-wtc", "category": "music", "difficulty": "hard",
     "goal": "Kimiko Ishizaka Open Well-Tempered Clavier",
     "description": "the CC0 'Open Well-Tempered Clavier' Bach recording (Book 1, 2015) by "
                    "Kimiko Ishizaka, FLAC or the original 24-bit files",
     "sig": r"ishizaka|open.?well.?tempered", "topic": r"well.?tempered|ishizaka|bach|clavier"},
    # ---- documents ------------------------------------------------------------------
    {"id": "voynich", "category": "documents", "difficulty": "medium",
     "goal": "Voynich manuscript high resolution scans Beinecke MS 408",
     "description": "full-resolution page scans (TIFF/JPEG) or a complete PDF facsimile of "
                    "every folio, from the Yale Beinecke digitization",
     "sig": r"voynich", "topic": r"voynich|beinecke|ms.?408"},
    {"id": "apollo11-flightplan", "category": "documents", "difficulty": "medium",
     "goal": "Apollo 11 flight plan final NASA 1969",
     "description": "the official Apollo 11 Flight Plan document (final version, July 1969) "
                    "as a scanned PDF from NASA/JSC",
     "sig": r"apollo.?11.*flight.?plan|flight.?plan.*apollo.?11", "topic": r"apollo"},
    {"id": "rfc793", "category": "documents", "difficulty": "easy",
     "goal": "RFC 793 Transmission Control Protocol original 1981 specification",
     "description": "the original RFC 793 text (September 1981, Postel), .txt or PDF",
     "sig": r"rfc.?793|transmission control protocol", "topic": r"\brfc\b|\btcp\b|transmission control"},
    # ---- software ---------------------------------------------------------------------
    {"id": "ubuntu-warty", "category": "software", "difficulty": "hard",
     "goal": "Ubuntu 4.10 Warty Warthog install CD ISO",
     "description": "the original October 2004 Ubuntu 4.10 'Warty Warthog' i386 install ISO",
     "sig": r"warty|ubuntu.?4\.10", "topic": r"ubuntu|warty"},
    {"id": "debian-bo", "category": "software", "difficulty": "hard",
     "goal": "Debian 1.3 bo CD images 1997",
     "description": "the Debian GNU/Linux 1.3 ('bo', 1997) CD ISO images or the full archive",
     "sig": r"debian.*(1\.3|\bbo\b)|\bbo\b.*debian", "topic": r"debian"},
    # ---- other / data ---------------------------------------------------------------------
    {"id": "mnist", "category": "other", "difficulty": "easy",
     "goal": "MNIST handwritten digits original idx files",
     "description": "the original four MNIST idx files (train/test images + labels) from "
                    "Yann LeCun's site or a faithful mirror",
     "sig": r"mnist", "topic": r"mnist|handwritten|digits|lecun"},
]

BY_ID = {t["id"]: t for t in BENCH}
