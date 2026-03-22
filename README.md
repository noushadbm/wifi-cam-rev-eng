### Steps

Setting up python environment and activating it.
```
$sudo apt install python3-dev build-essential -y
$python3 -m venv ~/venv
$source ~/venv/bin/activate
```

Installing required libraries
```
(venv)$ pip install netifaces
```

Running the code
```
DEBUG=1 python3 p2p_lansearch_v11_working_av.py
```
It will generate video file (stream.mjpeg) and audio file (stream.raw)

Playing the files:
```
# Play audio only
ffplay -f mulaw -ar 8000 -ac 1 stream.raw

# Play video only  
ffplay -f mjpeg stream.mjpeg

# Mux into MP4 with synchronized audio+video
ffmpeg -f mjpeg -i stream.mjpeg \
       -f mulaw -ar 8000 -ac 1 -i stream.raw \
       -c:v libx264 -c:a aac \
       output_av.mp4

# Play the muxed result
ffplay output_av.mp4
```