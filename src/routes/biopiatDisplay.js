const express = require('express');
const router = express.Router();
const biopiatDisplayController = require('../controllers/biopiatDisplayController');

// Playlist endpoints (device-facing)
router.get('/playlist', biopiatDisplayController.getPlaylist);
router.post('/device/:deviceId/ack', biopiatDisplayController.acknowledgePlaylist);
router.post('/device/:deviceId/heartbeat', biopiatDisplayController.deviceHeartbeat);

// Content management (admin)
router.get('/content', biopiatDisplayController.listContent);
router.post('/content', biopiatDisplayController.createContent);
router.put('/content/:id', biopiatDisplayController.updateContent);
router.delete('/content/:id', biopiatDisplayController.deleteContent);
router.post('/content/upload-url', biopiatDisplayController.getUploadUrl);

// Playlist management (admin)
router.get('/playlists', biopiatDisplayController.listPlaylists);
router.post('/playlists', biopiatDisplayController.createPlaylist);
router.get('/playlists/:id', biopiatDisplayController.getPlaylistById);
router.put('/playlists/:id', biopiatDisplayController.updatePlaylist);
router.delete('/playlists/:id', biopiatDisplayController.deletePlaylist);
router.post('/playlists/:id/publish', biopiatDisplayController.publishPlaylist);
router.post('/playlists/:id/items', biopiatDisplayController.addPlaylistItem);
router.put('/playlists/:id/items/reorder', biopiatDisplayController.reorderPlaylistItems);
router.delete('/playlists/:id/items/:itemId', biopiatDisplayController.removePlaylistItem);

// Device management (admin)
router.get('/devices', biopiatDisplayController.listDevices);
router.post('/devices', biopiatDisplayController.registerDevice);
router.get('/devices/:id', biopiatDisplayController.getDevice);
router.put('/devices/:id', biopiatDisplayController.updateDevice);
router.delete('/devices/:id', biopiatDisplayController.deleteDevice);

// Device groups (admin)
router.get('/groups', biopiatDisplayController.listDeviceGroups);
router.post('/groups', biopiatDisplayController.createDeviceGroup);
router.put('/groups/:id', biopiatDisplayController.updateDeviceGroup);
router.delete('/groups/:id', biopiatDisplayController.deleteDeviceGroup);
router.post('/groups/:id/devices', biopiatDisplayController.addDeviceToGroup);
router.delete('/groups/:id/devices/:deviceId', biopiatDisplayController.removeDeviceFromGroup);

// Urgent messages
router.post('/urgent-message', biopiatDisplayController.sendUrgentMessage);
router.get('/urgent-messages', biopiatDisplayController.listUrgentMessages);

module.exports = router;
